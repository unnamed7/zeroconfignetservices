using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Threading;
using System.Net.Sockets;
using System.Collections;

namespace ZeroconfService
{
	/// <summary>
	/// An exception that is thrown when a <see cref="NetService">NetService</see>
	/// or <see cref="NetServiceBrowser">NetServiceBrowser</see> dll error occurs.
	/// </summary>
	public class DNSServiceException : Exception
	{
		string s = null;
		string f = null;
		DNSServiceErrorType e = DNSServiceErrorType.kDNSServiceErr_NoError;

		internal DNSServiceException(string s)
		{
			this.s = s;
		}

		internal DNSServiceException(string function, DNSServiceErrorType error)
		{
			e = error;
			f = function;
			s = String.Format("An error occured in the function '{0}': {1}",
				function, error);
		}

		/// <summary>
		/// Creates a returns a string representation of the current exception
		/// </summary>
		/// <returns></returns>
		public override string ToString()
		{
			return s;
		}

		/// <summary>
		/// Gets a message that describes the current exception.
		/// </summary>
		public override string Message
		{
			get { return s; }
		}

		/// <summary>
		/// Gets the function name (if possible) that returned the underlying error
		/// </summary>
		public string Function { get { return f; } }
		/// <summary>
		/// Gets the <see cref="DNSServiceErrorType">DNSServiceErrorType</see> error
		/// that was returned by the underlying function.
		/// </summary>
		public DNSServiceErrorType ErrorType { get { return e; } }
	}

	/// <summary>
	/// The base class used by the <see cref="NetServiceBrowser">NetServiceBrowser</see>
	/// and <see cref="NetService">NetService</see> classes. This class primarily
	/// abstracts the asynchronous functionality of its derived classes.
	/// </summary>
	/// <remarks>
	/// It should not be necessary to derive from this class directly.
	/// </remarks>
	public abstract class DNSService
	{
		// Provides a mapping from sdRef's to their associated WatchSocket's
		private Hashtable sdRefToSocketMapping = Hashtable.Synchronized(new Hashtable());

		public static float GetVersion()
		{
			int version = 0;
			IntPtr result = IntPtr.Zero;

			try
			{
				UInt32 size = (UInt32)Marshal.SizeOf(typeof(UInt32));

				result = Marshal.AllocCoTaskMem((Int32)size);
				
				DNSServiceErrorType error = mDNSImports.DNSServiceGetProperty(mDNSImports.DNSServiceProperty_DaemonVersion, ref result, ref size);

				if (error != DNSServiceErrorType.kDNSServiceErr_NoError)
				{
					throw new DNSServiceException("DNSServiceGetProperty", error);
				}

				version = result.ToInt32();
			}
			finally
			{
				if (result != IntPtr.Zero) Marshal.FreeCoTaskMem(result);
			}

			// I have found no documenation that states how to parse a number into it's major/minor parts.
			// However, I have a few examples:
			// 1180500 = 118.5
			// 1760300 = 176.3

			int majorVersion = version / 10000;
			int minorVersion = version % 1000;

			return (float)majorVersion + (float)(minorVersion / 1000f);
		}

		private void PollInvokeable(IntPtr sdRef)
		{
			try
			{
				mDNSImports.DNSServiceProcessResult(sdRef);
			}
			catch (Exception e)
			{
				Console.WriteLine("Got an exception on DNSServiceProcessResult (Unamanaged, so via user callback?)\n{0}{1}", e, e.StackTrace);
			}
		}
		private delegate void PollInvokeableDelegate(IntPtr sdRef);

		private bool mAllowApplicationForms = true;
		/// <summary>
		/// Allows the application to attempt to post async replies over the
		/// application "main loop" by using the message queue of the first available
		/// open form (window). This is retrieved through
		/// <see cref="System.Windows.Forms.Application.OpenForms">Application.OpenForms</see>.
		/// </summary>
		public bool AllowApplicationForms
		{
			get { return mAllowApplicationForms; }
			set { mAllowApplicationForms = value; }
		}

		System.ComponentModel.ISynchronizeInvoke mInvokeableObject = null;
		/// <summary>
		/// Set the <see cref="System.ComponentModel.ISynchronizeInvoke">ISynchronizeInvoke</see>
		/// object to use as the invoke object. When returning results from asynchronous calls,
		/// the Invoke method on this object will be called to pass the results back
		/// in a thread safe manner.
		/// </summary>
		/// <remarks>
		/// This is the recommended way of using the DNSService class. It is recommended
		/// that you pass your main <see cref="System.Windows.Forms.Form">form</see> (window) in.
		/// </remarks>
		public System.ComponentModel.ISynchronizeInvoke InvokeableObject
		{
			get { return mInvokeableObject; }
			set { mInvokeableObject = value; }
		}

		private bool mAllowMultithreadedCallbacks = false;
		/// <summary>
		/// If this is set to true, <see cref="AllowApplicationForms">AllowApplicationForms</see>
		/// is set to false and <see cref="InvokeableObject">InvokeableObject</see> is set
		/// to null. Any time an asynchronous method needs to invoke a method in the
		/// main loop, it will instead run the method in its own thread.
		/// </summary>
		/// <remarks>
		/// <para>The thread safety of this property depends on the thread safety of
		/// the underlying dnssd.dll functions. Although it is not recommended, there
		/// are no known problems with this library using this method.
		/// </para>
		/// <para>
		/// If your application uses Windows.Forms or any other non-thread safe
		/// library, you will have to do your own invoking.
		/// </para>
		/// </remarks>
		public bool AllowMultithreadedCallbacks
		{
			get { return mAllowMultithreadedCallbacks; }
			set
			{
				mAllowMultithreadedCallbacks = value;
				if (mAllowMultithreadedCallbacks)
				{
					mAllowApplicationForms = false;
					mInvokeableObject = null;
				}
			}
		}

		internal void InheritInvokeOptions(DNSService fromService)
		{
			// We set the MultiThreadedCallback property first,
			// as it has the potential to affect the other properties.
			AllowMultithreadedCallbacks = fromService.AllowMultithreadedCallbacks;

			AllowApplicationForms = fromService.AllowApplicationForms;
			InvokeableObject = fromService.InvokeableObject;
		}

		private System.ComponentModel.ISynchronizeInvoke GetInvokeObject()
		{
			if (mInvokeableObject != null) return mInvokeableObject;

			if (mAllowApplicationForms)
			{
				// Need to post it to self over control thread
				FormCollection forms = System.Windows.Forms.Application.OpenForms;

				if (forms != null && forms.Count > 0)
				{
					Control control = forms[0];
					return control;
				}
			}
			return null;
		}

		/// <summary>
		/// Calls a method using the objects invokable object.
		/// </summary>
		/// <param name="method">The method to call.</param>
		/// <param name="args">The arguments to call the object with.</param>
		/// <returns>The result returned from method, or null if the method
		/// could not be invoked.</returns>
		protected object Invoke(Delegate method, params object[] args)
		{
			System.ComponentModel.ISynchronizeInvoke invokeable = GetInvokeObject();

			try
			{
				if (invokeable != null)
				{
					return invokeable.Invoke(method, args);
				}

				if (mAllowMultithreadedCallbacks)
				{
					return method.DynamicInvoke(args);
				}
			}
			catch { }

			return null;
		}

		private void AsyncPollCallback(IAsyncResult result)
		{
			WatchSocket socket = (WatchSocket)result.AsyncState;

			bool ret = socket.EndPoll(result);

			if (socket.Stopping)
			{
				// If we're stopping, don't process any results, and don't begin a new poll.
				return;
			}

			if (ret)
			{
				PollInvokeableDelegate cb = new PollInvokeableDelegate(PollInvokeable);
				Invoke(cb, socket.SDRef);
			}

			// The user may have stopped the socket during the Invoke above
			if (!socket.Stopping)
			{
				AsyncCallback callback = new AsyncCallback(AsyncPollCallback);
				socket.BeginPoll(-1, SelectMode.SelectRead, callback, socket);
			}
		}

		/// <summary>
		/// Starts polling the DNSService socket, and delegates
		/// data back to the primary DNSService API when data arrives
		/// on the socket.
		/// </summary>
		protected void SetupWatchSocket(IntPtr sdRef)
		{
			Int32 socketId = mDNSImports.DNSServiceRefSockFD(sdRef);
			WatchSocket socket = new WatchSocket(socketId, sdRef);

			sdRefToSocketMapping.Add(sdRef, socket);

			AsyncCallback callback = new AsyncCallback(AsyncPollCallback);
			IAsyncResult ar = socket.BeginPoll(-1, SelectMode.SelectRead, callback, socket);
		}

		/// <summary>
		/// This method tears down a previously setup watch socket.
		/// </summary>
		protected void TeardownWatchSocket(IntPtr sdRef)
		{
			WatchSocket socket = (WatchSocket)sdRefToSocketMapping[sdRef];

			if (socket != null)
			{
				socket.Stopping = true;

				// Note that we did not actually stop the poll.
				// This is because there is no way to actually stop the poll.
				// Our only option is to wait for the poll to finish.
				// And since we set the stopping variable, then no further action should be taken by the socket.
				// 
				// This should be fine, since when the DNSServiceRefDeallocate(sdRef) method is invoked,
				// the socket will be shutdown, and the poll will complete.

				sdRefToSocketMapping.Remove(sdRef);
			}
		}
	}
}
