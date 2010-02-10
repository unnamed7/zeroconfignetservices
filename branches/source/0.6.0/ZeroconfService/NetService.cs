using System;
using System.Collections.Generic;
using System.Collections;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

using System.Windows.Forms;
using System.Diagnostics;

namespace ZeroconfService
{
	/// <summary>
	/// <para>
	/// The NetService class represents a network service that your application publishes
	/// or uses as a client. This class, along with the browser class
	/// <see cref="NetServiceBrowser">NetServiceBrowser</see> use multicast DNS to
	/// communicate accross the local network.
	/// </para>
	/// <para>
	/// Your application can use this class to either publish information about
	/// a service, or as a client to retrieve information about another service.
	/// </para>
	/// <para>
	/// If you intend to publish a service, you must setup the service to publish and
	/// acquire a port on which the socket will recieve connections. You can then create
	/// a NetService instance to represent your service and publish it.
	/// </para>
	/// <para>
	/// If you intend to resolve a service, you can either use <see cref="NetServiceBrowser">NetServiceBrowser</see>
	/// to discover services of a given type, or you can create a new NetService object
	/// to resolve information about an known existing service.
	/// See <see cref="NetService(string,string,string)">NetService()</see>
	/// for information about creating new net services.
	/// </para>
	/// </summary>
	/// <remarks>
	/// <para>
	/// Network operations are performed asynchronously and are returned to your application
	/// via events fired from within this class. Events are typically fire in your
	/// application's main run loop, see <see cref="DNSService">DNSService</see> for information
	/// about controlling asynchronous events.
	/// </para>
	/// <para>
	/// It is important to note that this class uses the same asynchronous method to
	/// publish records as it does to fire events. So if you are simply publishing a service,
	/// you must still ensure that the <see cref="DNSService">DNSService</see> parent class
	/// is properly placed into a run loop.
	/// </para>
	/// </remarks>
	public sealed class NetService : DNSService, IDisposable
	{
		/// <summary>
		/// Represents the method that will handle <see cref="DidPublishService">DidPublishService</see>
		/// events from a <see cref="NetService">NetService</see> instance.
		/// </summary>
		/// <param name="service">Sender of this event.</param>
		public delegate void ServicePublished(NetService service);

		/// <summary>
		/// Occurs when a service is published.
		/// </summary>
		public event ServicePublished DidPublishService;

		/// <summary>
		/// Represents the method that will handle <see cref="DidNotPublishService">DidNotPublishService</see>
		/// events from a <see cref="NetService">NetService</see> instance.
		/// </summary>
		/// <param name="service">Sender of this event.</param>
		/// <param name="exception">The error that prevented the service from publishing.</param>
		public delegate void ServiceNotPublished(NetService service, DNSServiceException exception);

		/// <summary>
		/// Occurs when a service fails to be published.
		/// </summary>
		public event ServiceNotPublished DidNotPublishService;

		/// <summary>
		/// Represents the method that will handle <see cref="DidResolveService">DidResolveService</see>
		/// events from a <see cref="NetService">NetService</see> instance.
		/// </summary>
		/// <param name="service">Sender of this event.</param>
		public delegate void ServiceResolved(NetService service);

		/// <summary>
		/// Occurs when a service was resolved.
		/// </summary>
		public event ServiceResolved DidResolveService;

		/// <summary>
		/// Represents the method that will handle <see cref="DidNotResolveService">DidNotResolveService</see>
		/// events from a <see cref="NetService">NetService</see> instance.
		/// </summary>
		/// <param name="service">Sender of this event.</param>
		/// <param name="exception">The error that prevented the service from resolving.</param>
		public delegate void ServiceNotResolved(NetService service, DNSServiceException exception);

		/// <summary>
		/// Occurs when a service fails to be resolved.
		/// </summary>
		public event ServiceNotResolved DidNotResolveService;

		/// <summary>
		/// Represents the method that will handle <see cref="DidUpdateTXT">DidUpdateTXT</see>
		/// events from a <see cref="NetService">NetService</see> instance.
		/// </summary>
		/// <param name="service">Sender of this event.</param>
		public delegate void ServiceTXTUpdated(NetService service);

		/// <summary>
		/// Occurs when the TXT record for a given service was updated.
		/// </summary>
		/// <remarks>
		/// This event is not fired after you update the TXT record for an event yourself.
		/// </remarks>
		public event ServiceTXTUpdated DidUpdateTXT;

		private String mName;
		private String mType;
		private String mDomain;
		private int mPort;
		private byte[] mTXTRecordData;
		private String mHostName;
		private ArrayList mAddresses;

		private IntPtr sdRefA;
		private IntPtr sdRefB;
		private IntPtr sdRefC;

		private GCHandle gchSelfA;
		private GCHandle gchSelfB;
		private GCHandle gchSelfC;

		private mDNSImports.DNSServiceQueryReply queryReplyCb;
		private mDNSImports.DNSServiceQueryReply ipLookupReplyCb;
		private mDNSImports.DNSServiceResolveReply resolveReplyCb;
		private mDNSImports.DNSServiceRegisterReply registerReplyCb;

		private bool disposed = false;

		private System.Threading.Timer resolveTimer;

		/// <summary>
		/// Initializes a new instance of the NetService class for resolving.
		/// </summary>
		/// <param name="domain">The domain of the service. For the local domain, use <c>"local."</c> not <c>""</c>.</param>
		/// <param name="type"><para>The network service type.</para>
		/// <para>This must include both the transport type (<c>"_tcp."</c> or <c>".udp"</c>)
		/// and the service name prefixed with an underscore(<c>"_"</c>). For example, to search
		/// for an HTTP service on TCP you would use <c>"_http._tcp."</c></para></param>
		/// <param name="name">The name of the service to resolve.</param>
		/// <remarks>
		/// <para>This constructor is the appropriate constructor used to resolve a service.
		/// You can not use this constructor to publish a service.</para>
		/// </remarks>
		public NetService(string domain, string type, string name)
		{
			mDomain = domain;
			mType = type;
			mName = name;
		}

		/// <summary>
		/// Initializes a new instance of the NetService class for publishing.
		/// </summary>
		/// <param name="domain">
		/// <para>The domain of the service. For the local domain, use <c>"local."</c> not <c>""</c>.</para>
		/// <para>To us the default domain, simply parse <c>""</c>.</para>
		/// </param>
		/// <param name="type"><para>The network service type.</para>
		/// <para>This must include both the transport type (<c>"_tcp."</c> or <c>".udp"</c>)
		/// and the service name prefixed with an underscore(<c>"_"</c>). For example, to search
		/// for an HTTP service on TCP you would use <c>"_http._tcp."</c></para></param>
		/// <param name="name">The name of the service. This name must be unique.</param>
		/// <param name="port">The port number on which your service is available.</param>
		/// <remarks>
		/// <para>This constructor is the appropriate constructor used to publish a service.
		/// You can not use this constructor to resolve a service.</para>
		/// </remarks>
		public NetService(string domain, string type, string name, int port)
		{
			mDomain = domain;
			mType = type;
			mName = name;
			mPort = port;
		}

		/// <summary>
		/// Standard Destructor.
		/// </summary>
		~NetService()
		{
			Debug.WriteLine("NetService: Finalize");

			// Call our helper method.
			// Specifying "false" signifies that the GC triggered the clean up.
			CleanUp(false);
		}

		private void CleanUp(bool disposing)
		{
			if (!disposed)
			{
				if (disposing)
				{
					// Dispose managed resources here
				}

				// Clean up unmanaged resources here
				Stop();
				StopMonitoring();
			}
			disposed = true;
		}

		/// <summary>
		/// NetService objects make use of unmanaged resources.
		/// As such, they will not be properly garbage collected unless calls are balanced.
		/// Eg: Balance a call to Publish() with a call to Stop(), StartMonitoring() with StopMonitoring().
		/// Alternatively, the Dispose() method is available, which simply calls Stop() and StopMonitoring() on your behalf.
		/// </summary>
		public void Dispose()
		{
			Debug.WriteLine("NetService: Dispose");

			// Call our helper method.
			// Specifying "true" signifies that the object user triggered the clean up.
			CleanUp(true);

			// Now suppress finialization
			GC.SuppressFinalize(this);
		}

		/// <summary>
		/// Stops the currently running search or resolution.
		/// </summary>
		public void Stop()
		{
			if (resolveTimer != null)
			{
				resolveTimer.Dispose();
				resolveTimer = null;
			}

			TeardownWatchSocket(sdRefA);
			if (sdRefA != IntPtr.Zero)
			{
				mDNSImports.DNSServiceRefDeallocate(sdRefA);
				sdRefA = IntPtr.Zero;
			}

			resolveReplyCb = null;
			registerReplyCb = null;

			if (gchSelfA.IsAllocated)
			{
				gchSelfA.Free();
			}

			TeardownWatchSocket(sdRefC);
			if (sdRefC != IntPtr.Zero)
			{
				mDNSImports.DNSServiceRefDeallocate(sdRefC);
				sdRefC = IntPtr.Zero;
			}

			ipLookupReplyCb = null;

			if (gchSelfC.IsAllocated)
			{
				gchSelfC.Free();
			}
		}

		/// <summary>
		/// Attempts to advertise the service on the network.
		/// </summary>
		public void Publish()
		{
			Stop();

			registerReplyCb = new mDNSImports.DNSServiceRegisterReply(RegisterReply);
			gchSelfA = GCHandle.Alloc(this);

			DNSServiceErrorType err;

			UInt16 txtRecordLen = (UInt16)((TXTRecordData != null) ? TXTRecordData.Length : 0);
			UInt16 port = (UInt16)System.Net.IPAddress.HostToNetworkOrder((short)mPort);

			err = mDNSImports.DNSServiceRegister(out sdRefA, 0, 0, Name, Type, Domain, null, port, txtRecordLen, TXTRecordData, registerReplyCb, (IntPtr)gchSelfA);

			if (err == DNSServiceErrorType.kDNSServiceErr_NoError)
			{
				SetupWatchSocket(sdRefA);
			}
			else
			{
				Stop();
				if (DidNotPublishService != null)
				{
					DNSServiceException exception = new DNSServiceException("DNSServiceRegister", err);
					DidNotPublishService(this, exception);
				}
			}
		}

		/// <summary>
		/// Called with the result of the call to DNSServiceRegister() in the Publish() method.
		/// 
		/// If this object instance is configured with an <see cref="DNSService.InvokeableObject">InvokeableObject</see>,
		/// this method is called in a thread safe manner. Typically, this means it's called on the application main loop.
		/// </summary>
		/// <param name="sdRef">
		///		The DNSServiceRef initialized by DNSServiceRegister().
		/// </param>
		/// <param name="flags">
		///		Currently unused, reserved for future use.
		/// </param>
		/// <param name="errorCode">
		///		Will be kDNSServiceErr_NoError on success, otherwise will indicate the failure that occurred
		///		(including name conflicts, if the kDNSServiceFlagsNoAutoRename flag was used when registering.)
		///		Other parameters are undefined if errorCode is nonzero.
		/// </param>
		/// <param name="name">
		///		The service name registered (if the application did not specify a name in
		///		DNSServiceRegister(), this indicates what name was automatically chosen).
		/// </param>
		/// <param name="regtype">
		///		The type of service registered, as it was passed to the callout.
		/// </param>
		/// <param name="domain">
		///		The domain on which the service was registered (if the application did not
		///		specify a domain in DNSServiceRegister(), this indicates the default domain
		///		on which the service was registered).
		/// </param>
		/// <param name="context">
		///		The context pointer that was passed to the callout.
		///	</param>
		private void RegisterReply(IntPtr sdRef,
		                  DNSServiceFlags flags,
		              DNSServiceErrorType errorCode,
		                           String name,
		                           String regtype,
		                           String domain,
		                          IntPtr context)
		{
			if (errorCode == DNSServiceErrorType.kDNSServiceErr_NoError)
			{
				// Update name, type domain to match what was actually published
				mName = name;
				mType = regtype;
				mDomain = domain;

				if (DidPublishService != null)
				{
					DidPublishService(this);
				}
			}
			else
			{
				Stop();
				if (DidNotPublishService != null)
				{
					DNSServiceException exception = new DNSServiceException("DNSServiceRegister", errorCode);
					DidNotPublishService(this, exception);
				}
			}
		}

		/// <summary>
		/// Starts a resolve process with a timeout.
		/// </summary>
		/// <param name="seconds">The maximum number of seconds to attempt a resolve.</param>
		public void ResolveWithTimeout(int seconds)
		{
			Stop();
			
			resolveReplyCb = new mDNSImports.DNSServiceResolveReply(ResolveReply);
            gchSelfA = GCHandle.Alloc(resolveReplyCb);
			
			DNSServiceErrorType err;
			err = mDNSImports.DNSServiceResolve(out sdRefA, 0, 0, Name, Type, Domain, Marshal.GetFunctionPointerForDelegate(resolveReplyCb), IntPtr.Zero);

			if (err == DNSServiceErrorType.kDNSServiceErr_NoError)
			{
				SetupWatchSocket(sdRefA);

				resolveTimer = new System.Threading.Timer(new TimerCallback(ResolveTimerCallback), resolveReplyCb, (seconds * 1000), Timeout.Infinite);
			}
			else
			{
				Stop();
				if (DidNotResolveService != null)
				{
					DNSServiceException exception = new DNSServiceException("DNSServiceResolve", err);
					DidNotResolveService(this, exception);
				}
			}
		}

		/// <summary>
		/// Called with the result of the call to DNSServiceResolve().
		/// 
		/// If this object instance is configured with an <see cref="DNSService.InvokeableObject">InvokeableObject</see>,
		/// this method is called in a thread safe manner. Typically, this means it's called on the application main loop.
		/// </summary>
		/// <param name="sdRef">
		///		The DNSServiceRef initialized by DNSServiceResolve().
		/// </param>
		/// <param name="flags">
		///		Currently unused, reserved for future use.
		/// </param>
		/// <param name="interfaceIndex">
		///		The interface on which the service was resolved.
		/// </param>
		/// <param name="errorCode">
		///		Will be kDNSServiceErr_NoError (0) on success, otherwise will indicate the failure that occurred.
		///		Other parameters are undefined if the errorCode is nonzero.
		/// </param>
		/// <param name="fullname">
		///		The full service domain name, in the form [servicename].[protocol].[domain].
		///		(This name is escaped following standard DNS rules, making it suitable for
		///		passing to standard system DNS APIs such as res_query(), or to the
		///		special-purpose functions included in this API that take fullname parameters.)
		/// </param>
		/// <param name="hosttarget">
		///		The target hostname of the machine providing the service.  This name can
		///		be passed to functions like gethostbyname() to identify the host's IP address.
		/// </param>
		/// <param name="port">
		///		The port, in network byte order, on which connections are accepted for this service.
		/// </param>
		/// <param name="txtLen">
		///		The length of the txt record, in bytes.
		/// </param>
		/// <param name="txtRecord">
		///		The service's primary txt record, in standard txt record format.
		/// </param>
		/// <param name="context">
		///		The context pointer that was passed to the callout.
		///	</param>
		private void ResolveReply(IntPtr sdRef,
		                 DNSServiceFlags flags,
		                          UInt32 interfaceIndex,
		             DNSServiceErrorType errorCode,
		                          String fullname,
		                          String hosttarget,
		                          UInt16 port,
		                          UInt16 txtLen,
		                          byte[] txtRecord,
		                          IntPtr context)
		{
			if (errorCode == DNSServiceErrorType.kDNSServiceErr_NoError)
			{
				// Update internal variables
				mHostName = hosttarget;
				mPort = ((int)System.Net.IPAddress.NetworkToHostOrder((short)port) & 0x0000ffff);

				// We may want to update the txt record.
				// The service may not have a txt record yet if it's never been monitored or resolved before.
				// Also, if it's not currently being monitored, then the returned txt record may include updates
				if (mTXTRecordData == null || !NetService.ByteArrayCompare(mTXTRecordData, txtRecord))
				{
					mTXTRecordData = txtRecord;

					// Invoke delegate if set
					if (DidUpdateTXT != null)
					{
						DidUpdateTXT(this);
					}
				}

				// At this point we have a host name, but we don't have the actual IP address.
				// We could use the Windows API's (System.Net.Dns.BeginGetHostEntry) to
				// convert from host name to IP, but they're painfully slow.
				// According to the following website (and my own personal testing),
				// using DNSServiceQueryRecord is much faster:
				// http://lists.apple.com/archives/Bonjour-dev/2006/Jan/msg00008.html

				//AsyncCallback cb = new AsyncCallback(c.AsyncGetHostEntryCallback);
				//IAsyncResult ar = System.Net.Dns.BeginGetHostEntry(hosttarget, cb, c);

				// Begin the process of looking up the IP address(es)
				IPLookup();
			}
			else
			{
				Stop();
				if (DidNotResolveService != null)
				{
					DNSServiceException exception = new DNSServiceException("DNSServiceResolve", errorCode);
					DidNotResolveService(this, exception);
				}
			}
		}

		/// <summary>
		/// This method begins the process of looking up the IP address(es) associated with the current hostname.
		/// </summary>
		private void IPLookup()
		{
			mAddresses = new ArrayList();

			ipLookupReplyCb = new mDNSImports.DNSServiceQueryReply(IPLookupReply);
			gchSelfC = GCHandle.Alloc(this);

			DNSServiceErrorType err;
			err = mDNSImports.DNSServiceQueryRecord(out sdRefC, 0, 0, HostName, DNSServiceType.kDNSServiceType_A, DNSServiceClass.kDNSServiceClass_IN, ipLookupReplyCb, (IntPtr)gchSelfC);

			if (err == DNSServiceErrorType.kDNSServiceErr_NoError)
			{
				SetupWatchSocket(sdRefC);
			}
			else
			{
				Stop();
				if (DidNotResolveService != null)
				{
					DNSServiceException exception = new DNSServiceException("DNSServiceQueryRecord", err);
					DidNotResolveService(this, exception);
				}
			}
		}

		/// <summary>
		/// Called with the result of the call to DNSServiceQueryRecord() in the IPLookup() method.
		/// 
		/// If this object instance is configured with an <see cref="DNSService.InvokeableObject">InvokeableObject</see>,
		/// this method is called in a thread safe manner. Typically, this means it's called on the application main loop.
		/// </summary>
		/// <param name="sdRef">
		///		The DNSServiceRef initialized by DNSServiceQueryRecord().
		/// </param>
		/// <param name="flags">
		///		Possible values are kDNSServiceFlagsMoreComing and kDNSServiceFlagsAdd.
		///		The Add flag is NOT set for PTR records with a ttl of 0, i.e. "Remove" events.
		/// </param>
		/// <param name="interfaceIndex">
		///		The interface on which the query was resolved.
		/// </param>
		/// <param name="errorCode">
		///		Will be kDNSServiceErr_NoError on success, otherwise will indicate the failure that occurred.
		///		Other parameters are undefined if errorCode is nonzero.
		/// </param>
		/// <param name="fullname">
		///		The resource record's full domain name.
		/// </param>
		/// <param name="rrType">
		///		The resource record's type (e.g. kDNSServiceType_PTR, kDNSServiceType_SRV, etc)
		/// </param>
		/// <param name="rrClass">
		///		The class of the resource record (usually kDNSServiceClass_IN).
		/// </param>
		/// <param name="rdLength">
		///		The length, in bytes, of the resource record rdata.
		/// </param>
		/// <param name="rData">
		///		The raw rdata of the resource record.
		/// </param>
		/// <param name="ttl">
		///		The resource record's time to live, in seconds.
		/// </param>
		/// <param name="context">
		///		The context pointer that was passed to the callout.
		/// </param>
		private void IPLookupReply(IntPtr sdRef,
		                  DNSServiceFlags flags,
		                           UInt32 interfaceIndex,
		              DNSServiceErrorType errorCode,
		                           String fullname,
		                   DNSServiceType rrType,
		                  DNSServiceClass rrClass,
		                           UInt16 rdLength,
		                           byte[] rData,
		                           UInt32 ttl,
		                           IntPtr context)
		{
			if (errorCode == DNSServiceErrorType.kDNSServiceErr_NoError)
			{
				if((flags & DNSServiceFlags.kDNSServiceFlagsAdd) > 0)
				{
					System.Net.IPAddress addr = new System.Net.IPAddress(rData);
					System.Net.IPEndPoint ep = new System.Net.IPEndPoint(addr, mPort);
					mAddresses.Add(ep);
				}

				if ((flags & DNSServiceFlags.kDNSServiceFlagsMoreComing) == 0)
				{
					Stop();
					if (DidResolveService != null)
					{
						DidResolveService(this);
					}
				}
			}
			else
			{
				Stop();
				if (DidNotResolveService != null)
				{
					DNSServiceException exception = new DNSServiceException("DNSServiceQueryRecord", errorCode);
					DidNotResolveService(this, exception);
				}
			}
		}

		/// <summary>
		/// Called (on a thread pool worker thread) when the resolve timer fires.
		/// </summary>
		/// <param name="state">The object passed to the timer during initialization.</param>
		private void ResolveTimerCallback(object state)
		{
			// Move execution to the proper thread
			Invoke(new ResolveTimerReplyDelegate(ResolveTimerReply), state);
		}

		/// <summary>
		/// Called when the resolve timer fires.
		/// 
		/// If this object instance is configured with an <see cref="DNSService.InvokeableObject">InvokeableObject</see>,
		/// this method is called in a thread safe manner. Typically, this means it's called on the application main loop.
		/// </summary>
		/// <param name="state">The object passed to the timer during initialization.</param>
		private void ResolveTimerReply(object state)
		{
			mDNSImports.DNSServiceResolveReply resolveReplyCbThen = (mDNSImports.DNSServiceResolveReply)state;
			if (resolveReplyCbThen == resolveReplyCb)
			{
				Stop();

				if (DidNotResolveService != null)
				{
					DNSServiceException exception = new DNSServiceException("Timeout", DNSServiceErrorType.kDNSServiceErr_Timeout);
					DidNotResolveService(this, exception);
				}
			}
		}
		private delegate void ResolveTimerReplyDelegate(object state);
		
//		private IAsyncResult asyncResultsHostEntry;
//		private void AsyncGetHostEntryCallback(IAsyncResult result)
//		{
//			asyncResultsHostEntry = result;
//			NetService c = (NetService)result.AsyncState;
//			
//			// We invoke the GetHostEntryFinished method on the proper thread.
//			// This allows us to update internal variables, and invoke the delegate method
//			// on the same thread the user is using.
//			Invoke(new MethodInvoker(GetHostEntryFinished));
//		}
//		
//		private void GetHostEntryFinished()
//		{
//			System.Net.IPHostEntry hostInfo = System.Net.Dns.EndGetHostEntry(asyncResultsHostEntry);
//			asyncResultsHostEntry = null;
//			
//			ArrayList endpoints = new ArrayList();
//			
//			foreach (System.Net.IPAddress address in hostInfo.AddressList)
//			{
//				System.Net.IPEndPoint ep = new System.Net.IPEndPoint(address, mPort);
//				endpoints.Add(ep);
//			}
//			mAddresses = endpoints;
//			
//			if (DidResolveService != null)
//				DidResolveService(this);
//		}

		/// <summary>
		/// Starts the monitoring of TXT-record updates for the receiver.
		/// </summary>
		public void StartMonitoring()
		{
			// Ignore the method call if we're already monitoring the service
			// More than one objects may be informed of TXT-record updates via the delegates
			if (queryReplyCb == null)
			{
				queryReplyCb = new mDNSImports.DNSServiceQueryReply(QueryReply);
				gchSelfB = GCHandle.Alloc(this);

				String fqdn = String.Format("{0}.{1}{2}", Name, Type, Domain);

				DNSServiceErrorType err;
				err = mDNSImports.DNSServiceQueryRecord(out sdRefB, DNSServiceFlags.kDNSServiceFlagsLongLivedQuery, 0, fqdn, DNSServiceType.kDNSServiceType_TXT, DNSServiceClass.kDNSServiceClass_IN, queryReplyCb, (IntPtr)gchSelfB);

				if (err == DNSServiceErrorType.kDNSServiceErr_NoError)
				{
					SetupWatchSocket(sdRefB);
				}
				else
				{
					throw new DNSServiceException("DNSServiceQueryRecord", err);
				}
			}
		}

		/// <summary>
		/// Stops the monitoring of TXT-record updates for the receiver.
		/// </summary>
		public void StopMonitoring()
		{
			TeardownWatchSocket(sdRefB);
			if (sdRefB != IntPtr.Zero)
			{
				mDNSImports.DNSServiceRefDeallocate(sdRefB);
				sdRefB = IntPtr.Zero;
			}
			
			queryReplyCb = null;

			if (gchSelfB.IsAllocated)
			{
				gchSelfB.Free();
			}
		}

		/// <summary>
		/// Called with the result of the call to DNSServiceQueryRecord() in the StartMonitoring() method.
		/// 
		/// If this object instance is configured with an <see cref="DNSService.InvokeableObject">InvokeableObject</see>,
		/// this method is called in a thread safe manner. Typically, this means it's called on the application main loop.
		/// </summary>
		/// <param name="sdRef">
		///		The DNSServiceRef initialized by DNSServiceQueryRecord().
		/// </param>
		/// <param name="flags">
		///		Possible values are kDNSServiceFlagsMoreComing and kDNSServiceFlagsAdd.
		///		The Add flag is NOT set for PTR records with a ttl of 0, i.e. "Remove" events.
		/// </param>
		/// <param name="interfaceIndex">
		///		The interface on which the query was resolved.
		/// </param>
		/// <param name="errorCode">
		///		Will be kDNSServiceErr_NoError on success, otherwise will indicate the failure that occurred.
		///		Other parameters are undefined if errorCode is nonzero.
		/// </param>
		/// <param name="fullname">
		///		The resource record's full domain name.
		/// </param>
		/// <param name="rrType">
		///		The resource record's type (e.g. kDNSServiceType_PTR, kDNSServiceType_SRV, etc)
		/// </param>
		/// <param name="rrClass">
		///		The class of the resource record (usually kDNSServiceClass_IN).
		/// </param>
		/// <param name="rdLength">
		///		The length, in bytes, of the resource record rdata.
		/// </param>
		/// <param name="rData">
		///		The raw rdata of the resource record.
		/// </param>
		/// <param name="ttl">
		///		The resource record's time to live, in seconds.
		/// </param>
		/// <param name="context">
		///		The context pointer that was passed to the callout.
		/// </param>
		private void QueryReply(IntPtr sdRef,
		               DNSServiceFlags flags,
		                        UInt32 interfaceIndex,
		           DNSServiceErrorType errorCode,
		                        String fullname,
		                DNSServiceType rrType,
		               DNSServiceClass rrClass,
		                        UInt16 rdLength,
		                        byte[] rData,
		                        UInt32 ttl,
		                        IntPtr context)
		{
			if (errorCode == DNSServiceErrorType.kDNSServiceErr_NoError)
			{
				mTXTRecordData = rData;

				if (DidUpdateTXT != null)
				{
					DidUpdateTXT(this);
				}
			}
		}

		/// <summary>
		/// Returns a <c>byte[]</c> object representing a TXT record
		/// from a given dictionary.
		/// </summary>
		/// <param name="dict">
		///		A dictionary containing a TXT record.
		/// </param>
		/// <returns>
		///		A <c>byte[]</c> object representing TXT data formed from <c>dict</c>.
		/// </returns>
		/// <remarks>
		/// <para>
		///		The dictionary must contain a set of key / value pairs representing a TXT record.
		/// </para>
		/// <para>
		///		The key objects must be <see cref="System.String">String</see> objects.
		///		These will be converted to UTF-8 format by this method.
		/// </para>
		/// <para>
		///		The value objects must be either <see cref="System.String">String</see> objects or byte[] data.
		///		String values will be converted to UTF-8 format by this method.
		/// </para>
		/// </remarks>
		public static byte[] DataFromTXTRecordDictionary(IDictionary dict)
		{
			// The format of TXT Records:
			// The TXT Record consists of one or more strings, each of which consists of a single length byte,
			// followed by 0-255 bytes of text. An example of such a string is:
			// | 0x08 | p | a | p | e | r | = | A | 4 |
			//
			// The first byte of data is a binary byte with value 8.
			// It is then followed by eight more bytes of data, each containing the ASCII (or UTF-8) codes
			// for the character indicated.
			// 
			// According to the DNS specification (RFC 1035), a TXT record must contain at least one string.
			// An empty TXT record with zero strings is not allowed. Because of this you may see TXT records
			// containing only a single | 0x0 | byte, meaning an empty string.
			//
			// -Adapted from "Zero Configuration Networking, The Definitive Guide", page 66

			// Todo: Solve dilemma of txt record entries bigger than 255 bytes.
			// See what apple does in their implementation, and follow suite.

			if (dict == null)
			{
				byte[] emptyTXTRecord = { 0 };
				return emptyTXTRecord;
			}

			List<byte[]> entries = new List<byte[]>();
			int totalLength = 0;
			foreach (DictionaryEntry kvp in dict)
			{
				String key = (String)kvp.Key;
				byte[] keyData = Encoding.UTF8.GetBytes(key);

				byte[] valueData;

				if (kvp.Value is string)
				{
					String value = (String)kvp.Value;
					valueData = Encoding.UTF8.GetBytes(value);
				}
				else
				{
					valueData = (byte[])kvp.Value;
				}

				byte[] entry;

				if (valueData == null)
				{
					byte length = (byte)(keyData.Length);
					entry = new byte[length+1];
					entry[0] = length;
					Buffer.BlockCopy(keyData, 0, entry, 1, keyData.Length);
				}
				else
				{
					byte length = (byte)(keyData.Length + 1 + valueData.Length);
					entry = new byte[length+1];
					entry[0] = length;
					Buffer.BlockCopy(keyData, 0, entry, 1, keyData.Length);
					entry[keyData.Length + 1] = (byte)'=';
					Buffer.BlockCopy(valueData, 0, entry, keyData.Length + 2, valueData.Length);
				}

				entries.Add(entry);
				totalLength += entry.Length;
			}

			byte[] result = new byte[totalLength];
			int i = 0;
			foreach (byte[] entry in entries)
			{
				Buffer.BlockCopy(entry, 0, result, i, entry.Length);
				i += entry.Length;
			}

			return result;
		}

		/// <summary>
		/// Returns an <c>IDictionary</c> representing a TXT record.
		/// </summary>
		/// <param name="txtRecord">
		///		A <c>byte[]</c> object encoding of a TXT record.
		/// </param>
		/// <returns>
		///		A dictionary representing a TXT record.
		///	</returns>
		public static IDictionary DictionaryFromTXTRecordData(byte[] txtRecord)
		{
			// The format of TXT Records:
			// The TXT Record consists of one or more strings, each of which consists of a single length byte,
			// followed by 0-255 bytes of text. An example of such a string is:
			// | 0x08 | p | a | p | e | r | = | A | 4 |
			//
			// The first byte of data is a binary byte with value 8.
			// It is then followed by eight more bytes of data, each containing the ASCII (or UTF-8) codes
			// for the character indicated.
			// 
			// According to the DNS specification (RFC 1035), a TXT record must contain at least one string.
			// An empty TXT record with zero strings is not allowed. Because of this you may see TXT records
			// containing only a single | 0x0 | byte, meaning an empty string.
			//
			// -Adapted from "Zero Configuration Networking, The Definitive Guide", page 66

			if(txtRecord == null) return null;

			Hashtable dict = new Hashtable();
			
			int i = 0;
			while (i < txtRecord.Length)
			{
				byte length = txtRecord[i];
				if (length > 0)
				{
					byte[] data = new byte[length];

					byte equalsat = 0;

					for (int j = 0; j < length; j++)
					{
						data[j] = txtRecord[i + 1 + j];
						byte equalsbyte = (byte)'=';
						if (data[j] == equalsbyte)
						{
							equalsat = (byte)j;
						}
					}
					/* data is either:
					 *    key
					 *    key=
					 *    key=value
					 * where 'key' is a UTF-8 string and value is binary data
					 */
					string key;
					byte[] value = null;

					if (equalsat > 0)
					{
						key = Encoding.UTF8.GetString(data, 0, equalsat);
						byte valuelen = (byte)(length - (equalsat + 1));
						value = new byte[valuelen];
						for (int j = 0; j < valuelen; j++)
						{
							value[j] = data[equalsat + 1 + j];
						}
					}
					else
					{
						key = Encoding.UTF8.GetString(data);
					}

					// Add key, value pair to dictionary
					dict.Add(key, value);
				}

				i += (length + 1);
			}

			return dict;
		}

		/// <summary>
		/// Gets the domain of the service.
		/// </summary>
		/// <remarks>
		/// This can be an explicit domain or it can contain the generic local (<c>"local."</c>) domain.
		/// </remarks>
		public string Domain
		{
			get { return mDomain; }
		}

		/// <summary>
		/// Gets the type of the service.
		/// </summary>
		public string Type
		{
			get { return mType; }
		}

		/// <summary>
		/// Gets the name of the service.
		/// </summary>
		public string Name
		{
			get { return mName; }
		}

		/// <summary>
		/// Gets the port of the service.
		/// </summary>
		public int Port
		{
			get { return mPort; }
		}

		/// <summary>
		/// Gets the host name of the computer providing the service.
		/// Returns null if a successful resolve has not occurred.
		/// </summary>
		public string HostName
		{
			get { return mHostName; }
		}

		/// <summary>
		/// <para>Gets an IList object representing the available addresses of the
		/// resolved service.</para>
		/// <para>The objects in the list are <see cref="System.Net.IPEndPoint">IPEndPoint</see>s</para>
		/// </summary>
		public IList Addresses
		{
			get { return mAddresses; }
		}		

		/// <summary>
		/// Gets or the TXT record data.
		/// </summary>
		public byte[] TXTRecordData
		{
			get { return mTXTRecordData; }
		}

		/// <summary>
		///		Sets the TXT record for the receiver, and returns a Boolean value that indicates whether the operation was successful.
		///		If the service is not currently published, this will always return true.
		///		Otherwise this method will attempt to update the txt record for the published service.
		/// </summary>
		/// <param name="data">
		///		The updated TXT record data.
		/// </param>
		/// <returns>
		///		TRUE if recordData is successfully set as the TXT record, otherwise FALSE.
		/// </returns>
		public bool setTXTRecordData(byte[] data)
		{
			if (registerReplyCb == null)
			{
				// The service isn't currently published, so we may freely update our internal variable
				mTXTRecordData = data;
				return true;
			}
			else
			{
				// The service is currently published, so if the txt record data has changed,
				// we'll need to publish those changes.

				if (!NetService.ByteArrayCompare(mTXTRecordData, data))
				{
					UInt16 dataLen = (UInt16)((data != null) ? data.Length : 0);

					DNSServiceErrorType err;
					err = mDNSImports.DNSServiceUpdateRecord(sdRefA, IntPtr.Zero, 0, dataLen, data, 0);
					
					if (err == DNSServiceErrorType.kDNSServiceErr_NoError)
					{
						mTXTRecordData = data;
						return true;
					}
					else
					{
						throw new DNSServiceException("DNSServiceUpdateRecord", err);
					}
				}
				else
				{
					// There's no difference between the currently published data, and the given data.
					// We can simply ignore the request.
					return true;
				}
			}
		}

		/// <summary>
		/// Utility method to compare two byte arrays to see if they contain the same data.
		/// </summary>
		/// <param name="data1">Byte array 1</param>
		/// <param name="data2">Byte array 2</param>
		/// <returns></returns>
		private static bool ByteArrayCompare(byte[] data1, byte[] data2)
		{
			if (data1 == null)
			{
				if(data2 == null)
					return true;
				else
					return false;
			}
			else if (data2 == null)
			{
				return false;
			}

			if(data1.Length != data2.Length) return false;

			for (int i = 0; i < data1.Length; i++)
			{
				if(data1[i] != data2[i]) return false;
			}
			return true;
		}
	}
}
