import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

//---------------------------------------------------------------------------
public class httptrace {
	static String strVersion = "1.0";
	
	

	static String strAbout = 
		    "\r\nhttptrace - TCP/HTTP trace utility\r\n\r\n"+
		    "Usage:  httptrace -help\r\n\r\n"+
		    "Version: " +strVersion+ " (see httptrace.sourceforge.org)\r\n"+
		    "Author:  Thorsten Sprenger (tsprenger@sourceforge.org)";

	static String strUsage = 
		    "\r\nUsage: java httptrace {options}  or Win32 (Microsoft JVM): JVIEW httptrace\r\n"+
		    "\r\nOptions are:\r\n"+
		    "  -listenport  \tTCP port on which httptrace listens (default: 80)\r\n"+
		    "  -tunnelhost  \thostname to which httptrace redirects data  (default: localhost)\r\n"+
		    "  -tunnelport  \tport to which httptrace redirects data (default: 80)\r\n"+
		    "  -tracefile   \tappend data to this file.\r\n"+
		    "               \tuse \"-tracefile stdout\" to write to console.\r\n"+
		    "  -pattern     \ttrace only data containing this text (enclosed in \"\")\r\n"+
		    "  -nodata      \tdo not trace data\r\n"+
		    "  -noheader    \tdo not trace HTTP header\r\n"+
		    "  -nocomments  \tdo not write any comments\r\n"+
		    "  -help        \tprint this help\r\n"+
		    "  -version     \tprint version\r\n"+
		    "  -ssl         \tprint use ssl to redirects data\r\n"+
		    "\r\nSamples:\r\n"+
		    "Listen on port 80 and send requests to www.xyz.com : \r\n"+
		    "  java httptrace -tunnelhost www.xyz.com\r\n\r\n"+
		    "Listen on port 80 and send requests to local port 81, omit HTTP header : \r\n"+
		    "  java httptrace -tunnelport 81 -noheader\r\n\r\n"+
		    "Listen on port 80 and send requests to localhost port 6714, but don't display\r\n"+
		    "window. Print every packet containing \"<?xml\" on console :\r\n"+
		    "  java httptrace -tunnelport 6714 -nogui -pattern \"<?xml\" -tracefile stdout \r\n";
	// httptrace parameters:
	static int iListenPort;
	static int iTunnelPort;
	static String strTunnelHost;
	static String strTraceFile;
	static String strPattern;
	static boolean bDisplayData;
	static boolean bDisplayHttpHeader;
	static boolean bDisplayComments;
	static boolean bParameterDialog;
	static boolean bhttps;

	static FileWriter fTrace;
	static DataTunnel inDataTunnel, outDataTunnel;

	// ---------------------------------------------------------------------------
	public httptrace() { // the constructor inits the main window

		TimeNow t = new TimeNow();
		putComment(1, "httptrace started at " + t.getDateTimeString());

		if (!bDisplayHttpHeader) {
			putComment(1, "HTTP headers are not displayed.");
		}
		if (!bDisplayData) {
			putComment(1, "Data is not displayed.");
		}

		putComment(1, "listenport=" + iListenPort + " tunnelhost=" + strTunnelHost + " tunnelport=" + iTunnelPort);
		if (strPattern.length() != 0) {
			putComment(1, "searching for pattern: " + strPattern);
		}
		if (strTraceFile.length() != 0) {
			putComment(1, "writing to file: " + strTraceFile);
		}
	}

	// ---------------------------------------------------------------------------
	// print a comment line to text area and trace file.
	// if level=1 then do not print if -nocomments is set
	public void putComment(int level, String txt) {
		if ((bDisplayComments) || (level == 0)) {
			String s = new String("\r\n> " + txt);
			WriteTraceFile(s);
		}
	}

	// ---------------------------------------------------------------------------
	// write a string to the tracefile (if -tracefile ist set)
	public void WriteTraceFile(String s) {
		if (strTraceFile.length() != 0) {
			if (strTraceFile.equalsIgnoreCase("stdout")) {
				System.out.print(s);
			} else {
				try {
					fTrace = new FileWriter(strTraceFile, true); // true=append
					fTrace.write(s);
					fTrace.close();
				} catch (IOException e) {
					System.err.println("cannot write to file " + strTraceFile);
					System.err.println(e.toString());
					return;
				}
			}
		}
	}

	// ---------------------------------------------------------------------------

	// ---------------------------------------------------------------------------
	public static void main(String args[]) throws IOException {

		if (!processArgs(args)) {
			return;
		}

		final httptrace ht = new httptrace();

		// create the server thread:
		Thread threadServer = new Thread() {
			public void run() {
				ServerSocket ss = null;
				try {
					ss = new ServerSocket(ht.iListenPort);
				} catch (Exception e) {
					e.printStackTrace();
					System.exit(1);
				}
				while (true) {
					try {
						Socket sock1 = ss.accept();
						Socket sock2 = new Socket(ht.strTunnelHost, ht.iTunnelPort);

						if (bhttps) {
							SSLSocketFactory ssf = createSslSocketFactory();
							SSLSocket sockSll2 = (SSLSocket) ssf.createSocket(sock2, ht.strTunnelHost, ht.iTunnelPort, true);
							sockSll2.startHandshake();
							new DataTunnel(ht, sock1.getInputStream(), sockSll2.getOutputStream(), "Request").start();
							new DataTunnel(ht, sockSll2.getInputStream(), sock1.getOutputStream(), "Response").start();

						} else {
							new DataTunnel(ht, sock1.getInputStream(), sock2.getOutputStream(), "Request").start();
							new DataTunnel(ht, sock2.getInputStream(), sock1.getOutputStream(), "Response").start();

						}

					} catch (Exception ee) {
						ee.printStackTrace();
					}
				}
			}
		};
		threadServer.start();
	}

	public static SSLSocketFactory createSslSocketFactory() throws Exception {
		TrustManager[] byPassTrustManagers = new TrustManager[] { new X509TrustManager() {
			public X509Certificate[] getAcceptedIssuers() {
				return new X509Certificate[0];
			}

			public void checkClientTrusted(X509Certificate[] chain, String authType) {
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) {
			}
		} };
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(null, byPassTrustManagers, new SecureRandom());
		return sslContext.getSocketFactory();
	}

	// ---------------------------------------------------------------------------
	// read parameters from command line:
	public static boolean processArgs(String[] args) {
		iListenPort = 80; // defaults
		strTunnelHost = "localhost";
		iTunnelPort = 80;
		strTraceFile = "";
		strPattern = "";
		bDisplayHttpHeader = true;
		bDisplayData = true;
		bDisplayComments = true;
		bhttps = false;

		for (int i = 0; i < args.length; i++) {
			String arg = args[i];

			if (arg.equalsIgnoreCase("-help") || arg.equalsIgnoreCase("help") || arg.equalsIgnoreCase("-?") || arg.equalsIgnoreCase("/?")) {
				System.out.println(strUsage);
				return false;
			} else if (arg.equalsIgnoreCase("-listenport")) {
				i++;
				iListenPort = Integer.parseInt(args[i]);
			} else if (arg.equalsIgnoreCase("-tunnelport")) {
				i++;
				iTunnelPort = Integer.parseInt(args[i]);
			} else if (arg.equalsIgnoreCase("-tunnelhost")) {
				i++;
				strTunnelHost = args[i];
			} else if (arg.equalsIgnoreCase("-tracefile")) {
				i++;
				strTraceFile = args[i];
			} else if (arg.equalsIgnoreCase("-pattern")) {
				i++;
				strPattern = args[i];
			} else if (arg.equalsIgnoreCase("-nodata")) {
				bDisplayData = false;
			} else if (arg.equalsIgnoreCase("-noheader")) {
				bDisplayHttpHeader = false;
			} else if (arg.equalsIgnoreCase("-nocomments")) {
				bDisplayComments = false;
			} else if (arg.equalsIgnoreCase("-version")) {
				System.out.println(strAbout);
				return false;
			} else if (arg.equalsIgnoreCase("-ssl")) {
				bhttps = true;
			} else {
				System.out.println(strAbout);
				return false;
			}
		}
		return true;
	}
} // end of class httptrace

// --------------------------------------------------------------------------

// ---------------------------------------------------------------------------
class TimeNow {
	GregorianCalendar cal;
	String strTime;

	TimeNow() {
		cal = new GregorianCalendar();
	}

	public String getDateTimeString() {
		strTime = cal.get(Calendar.YEAR) + "/" + cal.get(Calendar.MONTH) + "/" + cal.get(Calendar.DATE) + " " + cal.get(Calendar.HOUR_OF_DAY) + ":" + cal.get(Calendar.MINUTE) + ":" + cal.get(Calendar.SECOND);
		return (strTime);
	}

	public String getTimeString() {
		strTime = cal.get(Calendar.HOUR_OF_DAY) + ":" + cal.get(Calendar.MINUTE) + ":" + cal.get(Calendar.SECOND);
		return (strTime);
	}
}

// ---------------------------------------------------------------------------
// this thread is started twice:
// one thread for the client request, the other for the server response.
class DataTunnel extends Thread {
	final static int BUFSIZ = 1000;
	InputStream in;
	OutputStream out;
	byte buf[] = new byte[BUFSIZ];
	String direction;
	httptrace ht;

	DataTunnel(httptrace ht, InputStream in, OutputStream out, String direction) {
		this.ht = ht;
		this.in = in;
		this.out = out;
		this.direction = direction;
	}

	public void run() {
		int n;
		int iHttpHeaderEnd; // position of HTTP header end in packet
		int iDataPos; // postition of HTTP data start in packet
		boolean bHttpHeader;
		String s;
		String strBuf;

		iDataPos = 0;
		try {
			while ((n = in.read(buf)) > 0) {

				// write to TCPIP port:
				out.write(buf, 0, n);
				out.flush();
				iDataPos = 0;

				// is HTTP header in buffer?
				strBuf = new String(buf, 0, n);
				if (strBuf.indexOf("HTTP/1") != -1)
					bHttpHeader = true;
				else
					bHttpHeader = false;

				// do this only on start of a HTTP transaction:
				// iDataPos marks the begin of HTTP data (after HTTP header):
				if (bHttpHeader) {
					bHttpHeader = false;

					// display time stamp:
					TimeNow t = new TimeNow();
					ht.putComment(1, "\r\n---- HTTP " + direction + " at " + t.getDateTimeString() + " ----\r\n");

					// search for end of HTTP header (2 line feeds):
					strBuf = new String(buf, 0, n);
					iHttpHeaderEnd = strBuf.indexOf("\n\n");
					if (iHttpHeaderEnd == -1) {
						// if not found, try again with DOS line feeds:
						iHttpHeaderEnd = strBuf.indexOf("\r\n\r\n");
					}
					if (iHttpHeaderEnd == -1)
						iDataPos = 0; // if no HTTP header end,
					else // then display all from start
						iDataPos = iHttpHeaderEnd + 2;
				}

				s = "";
				if (!ht.bDisplayHttpHeader && ht.bDisplayData) // display no
				                                               // HTTP header,
				                                               // only data
				{
					s = new String(buf, iDataPos, n);
				}

				if (ht.bDisplayHttpHeader && !ht.bDisplayData) // display no
				                                               // data, only
				                                               // header
				{
					s = new String(buf, 0, iDataPos);
				}

				if (ht.bDisplayHttpHeader && ht.bDisplayData) // display both
				                                              // header and data
				{
					s = new String(buf, 0, n);
				}

				// only if there is a search pattern, search for it.
				if ((ht.strPattern.length() == 0) || (strBuf.indexOf(ht.strPattern) != -1)) {
					ht.WriteTraceFile(s); // write to file
				}

				iDataPos = 0; // after header packet:
				              // for all following packets, display whole packet
			}
		} catch (IOException e) {
		} finally {
			try {
				in.close();
				out.close();
			} catch (IOException e) {
			}
		}
	}

}
