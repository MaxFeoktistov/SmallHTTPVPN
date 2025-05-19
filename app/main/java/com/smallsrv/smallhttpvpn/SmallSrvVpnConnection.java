/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2024 Maksim Feoktistov
 * Adapted Android example to Small HTTP server HTTPS VPN
 * Contact addresses for Email:  support@smallsrv.com
 */

package com.smallsrv.smallhttpvpn;

import static android.content.Context.MODE_PRIVATE;

import android.app.PendingIntent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
//import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyStore;
//import java.security.cert.Certificate;
import java.security.Security;
import java.security.cert.CertificateException;
//import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.Conscrypt;

public class SmallSrvVpnConnection implements Runnable {
    /**
     * Callback interface to let the {@link SmallSrvVpnService} know about new connections
     * and update the foreground notification with connection status.
     */
    public interface OnEstablishListener {
        void onEstablish(ParcelFileDescriptor tunInterface);
    }
    private  long ipv4 = 0;
    private  String mUser;
    private  String mPatch;
    private  String mServerName;
    private int mServerPort = 443;
    public   Socket socket;
    public SSLSocket sslSocket;
    private SSLSocketFactory sslSocketFactory = null;

    private  String mRoute = "0.0.0.0";
    private  int mRoutepr = 0;

    /** Maximum packet size is constrained by the MTU, which is given as a signed short. */
    private static final int MAX_PACKET_SIZE = Short.MAX_VALUE;

    /** Time to wait in between losing the connection and retrying. */
    private static final long RECONNECT_WAIT_MS = TimeUnit.SECONDS.toMillis(3);

    /** Time between keepalives if there is no traffic at the moment.
     *
     * TODO: don't do this; it's much better to let the connection die and then reconnect when
     *       necessary instead of keeping the network hardware up for hours on end in between.
     **/
    private static final long KEEPALIVE_INTERVAL_MS = TimeUnit.SECONDS.toMillis(120);

    /** Time to wait without receiving any response before assuming the server is gone. */
    private static final long RECEIVE_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(20);

    /**
     * Time between polling the VPN interface for new traffic, since it's non-blocking.
     *
     * TODO: really don't do this; a blocking read on another thread is much cleaner.
     */
    private static final long IDLE_INTERVAL_MS = TimeUnit.MILLISECONDS.toMillis(100);

    /**
     * Number of periods of length {@IDLE_INTERVAL_MS} to wait before declaring the handshake a
     * complete and abject failure.
     *
     * TODO: use a higher-level protocol; hand-rolling is a fun but pointless exercise.
     */
    private static final int MAX_HANDSHAKE_ATTEMPTS = 50;

    private final SmallSrvVpnService mService;
    private final int mConnectionId;

    private final String mSharedSecret;
    private PendingIntent mConfigureIntent;
    private OnEstablishListener mOnEstablishListener;

    private int mMtu = 1500;
    public boolean connected = false;
    public boolean stop_thread = false;

    public long in_counter = 0;
    public long out_counter = 0;
    public long in_bytes = 0;
    public long out_bytes = 0;
    boolean msg_sendet = false;
    boolean LAN_only = false;

    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    public static final String[] TLSv = {"TLS", "TLSv1.3", "TLSv1.2", "TLSv1.1"};

    public  static final String[] enabledProtocols = {"TLSv1.3", "TLSv1.2"};
    public  static int   workTLS = 0;
    public  static int   TLStried = 0;
    public  static final int TLSmask = 3;
    public  static final int TriedMask = 0xF;
    public static boolean provederUpdated = false;

    static long easyHash(byte[] src)
    {
      long r1 = 0;
      long r2 = 0;
      int i=1;
      long xor = 0;
      for(long a: src) {
          r1+=a<<(i&0xF);
          r2+=r1 * (a|5);
          xor ^= a;
          i++;
      }
      return (r1 ^ (r2<<24)) + (xor<<42);
    };

    public SmallSrvVpnConnection(final SmallSrvVpnService service, final int connectionId,
            final String serverName,
            final String user,
            final String sharedSecret,
            boolean lo
    ) {
        mService = service;
        mConnectionId = connectionId;

        mUser = user;
        mSharedSecret = sharedSecret;
        LAN_only = lo;

        String t;
        int b = serverName.indexOf("http://");
        if(b == 0)
          t = serverName.substring(7);
        else {
            b = serverName.indexOf("https://");
            if (b == 0)
                t = serverName.substring(8);
            else
                t = serverName;
        }

        b = t.indexOf('/');
        if(b<=0)
        {
            stop_thread = true;
            throw new IllegalArgumentException(serverName);
        }
        mPatch = t.substring(b + 1 );
        mServerName = t.substring(0, b);
        mServerPort = 443;
        if(mServerName.indexOf('[') == 0 )
        {
            b = mServerName.indexOf(']');
            if(b>0)
                b=mServerName.indexOf(':', b);
        }
        else b=mServerName.indexOf(':');
        if(b>0) {
            mServerPort = Integer.parseInt(mServerName.substring(b+1),10);
            mServerName = mServerName.substring(0, b);
        }

        if(!provederUpdated) {
            Security.insertProviderAt(Conscrypt.newProvider(), 1);
            provederUpdated = true;
        }
    }

    /**
     * Optionally, set an intent to configure the VPN. This is {@code null} by default.
     */
    public void setConfigureIntent(PendingIntent intent) {
        mConfigureIntent = intent;
    }

    public void setOnEstablishListener(OnEstablishListener listener) {
        mOnEstablishListener = listener;
    }

    @Override
    public void run() {
        try {
            // We try to create the tunnel several times.
            // TODO: The better way is to work with ConnectivityManager, trying only when the
            // network is available.
            // Here we just use a counter to keep things simple.
            msg_sendet = false;
            for (int attempt = 0; attempt < 9 && ! stop_thread ; ++attempt) {
                // Reset the counter if we were connected.
                socket = null;
                if (run(0)) {
                    attempt = 0;
                }
                // Sleep for a while. This also checks if we got interrupted.
                if(stop_thread) break;
                if((TLStried & (1 << workTLS)) != 0)
                   Thread.sleep(3000);
            }
            Log.i(getTag(), "Giving up");
        } catch (IOException | IllegalStateException | InterruptedException | IllegalArgumentException e) {
            Log.e(getTag(), "Connection failed, exiting", e);
        }
        if(!msg_sendet) mService.mHandler.sendEmptyMessage(R.string.disconnected);
    }

    private TrustManager[] getWrappedTrustManagers(TrustManager[] trustManagers) {
        final X509TrustManager originalTrustManager = (X509TrustManager) trustManagers[0];
        return new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return originalTrustManager.getAcceptedIssuers();
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        try {
                            originalTrustManager.checkClientTrusted(certs, authType);
                        } catch (CertificateException ignored) {
                            Log.e(getTag(), "checkClientTrusted");
                        }
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        try {
                            //Log.i(getTag(), "Lb cSt 2");
                            originalTrustManager.checkServerTrusted(certs, authType);
                        } catch (CertificateException ignored) {
                            //Log.e(getTag(), "checkServerTrusted " +  authType);
                            X500Principal p;
                            mService.VrongSert = certs[0].getSubjectX500Principal().getName();
                            p = certs[0].getIssuerX500Principal();
                            mService.Issuer = ((p!=null)? p.getName() : "no issuer");
                            mService.hashSign = easyHash(certs[0].getSignature());
                            mService.hashPkey = easyHash(certs[0].getPublicKey().getEncoded());
                            String tmp = new String( certs[0].getPublicKey().toString() );
                            int pos = tmp.indexOf('=')+1;
                            mService.Issuer += String.format("\nNot after: %s\nkey: %s ...",  certs[0].getNotAfter().toString(), tmp.substring(pos,pos + 24) );
                            final SharedPreferences prefs = mService.getSharedPreferences("sert", MODE_PRIVATE);
                            String sn = mService.VrongSert;
                            sn = sn.replaceAll("[^a-zA-Z0-9]+","_");
                            Log.i(getTag(), String.format("checkServerTrusted %s\n%s ", sn, mService.VrongSert) );
                            long k = prefs.getLong(sn,0);
                            if(k != mService.hashPkey) {
                                mService.iStatus = -1;
                                mService.mHandler.sendEmptyMessage(R.string.new_ser);
                                connected = false;
                                stop_thread = true;
                                msg_sendet = true;
                            }
                        }
                    }
                }
        };
    }

    class HTTPReq{
        public String req;
        HTTPReq(String p) {
            req = new String("GET /" + p + " HTTP/1.1\r\n" );
        }
        public void setRequestProperty(String name, String val)
        {  req += name + ": " + val + "\r\n";
        }
        public String getHeaderField(String n)
        {
            String r;
             int bg1 = req.indexOf(n+":");
             if(bg1<0) return null;
             int l=n.length();
             bg1+=l;
             int e=req.indexOf('\r', bg1);
             bg1 ++;
             while(req.charAt(bg1) == 0x20) bg1++;

             r=req.substring(bg1,e);
             return r;
        }
    };

    class RecvThread extends Thread {
        public InputStream s_in;
        public FileOutputStream out;

        public RecvThread(InputStream i, FileOutputStream o) {
            super();
            s_in = i;
            out = o;
        }

        @Override
        public void run() {
            int length;
            int in_buf = 0;
            int recv_len;
            int recv_len2;

            byte[] rb_packet = new byte[MAX_PACKET_SIZE + 2];
            ByteBuffer r_packet = ByteBuffer.wrap(rb_packet, 0, MAX_PACKET_SIZE + 2);
            r_packet.order(ByteOrder.LITTLE_ENDIAN);

            try {
                while (socket.isConnected() && connected) {

                    length = s_in.read(rb_packet, in_buf, MAX_PACKET_SIZE + 2 - in_buf);
                    if(stop_thread) break;

                    if (length > 0) {
                        in_buf += length;
                        r_packet.limit(in_buf);
                        while (in_buf > 2) {
                            recv_len = r_packet.getShort(0);
                            recv_len2 = recv_len + 2;
                            if (recv_len2 > in_buf) break;
                            out.write(rb_packet, 2, recv_len);
                            in_counter++;
                            in_bytes += recv_len2;

                            in_buf -= recv_len2;
                            if (in_buf > 0) {
                                System.arraycopy(rb_packet, recv_len2, rb_packet, 0, in_buf);
                                r_packet.limit(in_buf);
                            } else {
                                r_packet.clear();
                                in_buf = 0;
                            }
                        }
                    } else if (length < 0) {
                        connected = false;
                        Log.i(getTag(), String.format("Connection closed: %d", length));
                        break;
                    }
                }
            } catch (IOException e) {
                Log.e(getTag(), "IO Error", e);
            }
            connected = false;
        }
    }

    private SSLSocketFactory getSSLSocketFactory() {
      int n = 4 - workTLS;
      while(n>0) {
        n--;
        try {
          KeyStore keyStore = KeyStore.getInstance("BKS");
          keyStore.load(null, null);

          String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
          TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
          tmf.init(keyStore);
          //Log.i(getTag(), "Lb gsf 1 " + tmfAlgorithm + " " + TLSv[workTLS]);
          SSLContext sslContext = SSLContext.getInstance(TLSv[workTLS]);

          sslContext.init(null, getWrappedTrustManagers(tmf.getTrustManagers()), null);

          return sslContext.getSocketFactory();
        } catch (Exception e) {
          Log.i(getTag(), "gsf error: " + e.toString());
          if(workTLS == 0) {
            workTLS=(workTLS + 1) & TLSmask;
            Log.i(getTag(), "Try with " + TLSv[workTLS]);
            continue ;
          }
          return HttpsURLConnection.getDefaultSSLSocketFactory();
        }
      }
      return HttpsURLConnection.getDefaultSSLSocketFactory();
    };

    //private final Semaphore mSem = new Semaphore(0, false);
    public int E64X(int i)
    {
        if(i==63)return '/';
        if(i==62)return '+';
        if(i>=52)return '0'+(i-52);
        if(i>=26)return 'a'+(i-26);
        return 'A'+i;
    };
    public int GetBit(String s,int i)
    {
        int t = s.charAt(i>>3);
        return   (t >> (7-(i&7)) ) &1;
    };

    public byte[] mEncode64(String s)
    {
        int i,j,k,n = 0;
        int cnt= s.length()*8;
        int mod = cnt%6;
        byte[] t = new byte[cnt/6+mod];
        for(i=0; i<cnt;)
        {
            for(j=k=0; k<6; k++,i++)
            {
                j<<=1;
                j|=GetBit(s,i);
            };
            t[n]= (byte) E64X(j);
            n++;
        }

        while(mod > 0)
        {
          t[n++]='=';
          mod--;
        }
        return t;
    };


    private boolean run(int debug_mode)
            throws IOException, InterruptedException, IllegalArgumentException {
        ParcelFileDescriptor iface = null;
        int code;
        boolean ret = false;
        connected = false;

        TLStried |= (1<<workTLS);


          //Log.i(getTag(), "Lb 1 ");
          // Create a https channel as the VPN tunnel.
        try  {
          //Log.i(getTag(), "Lb 2");
          //if( sslSocketFactory == null)
          {
            sslSocketFactory = getSSLSocketFactory();
          }

          socket = new Socket();
          socket.setKeepAlive(true);
          socket.setTcpNoDelay(true);

          Log.i(getTag(), "Connect... " + TLSv[workTLS] + " TLStried = " + TLStried );
          socket.connect(new InetSocketAddress(mServerName, mServerPort), 5000);

          sslSocket = (SSLSocket) sslSocketFactory.createSocket(socket, mServerName, mServerPort, false);

          sslSocket.setEnabledProtocols(enabledProtocols);

         // Log.i(getTag(), "Lb 2a");

          HTTPReq tunel = new HTTPReq(mPatch);

          tunel.setRequestProperty("Host", mServerName);
          String userpass = new String(mUser + ":" + mSharedSecret);
          if (Build.VERSION.SDK_INT >= 26 /*Build.VERSION_CODES.LOLLIPOP*/) {
            tunel.setRequestProperty("Authorization", "Basic " + new String(Base64.getEncoder().encode(userpass.getBytes())));
          }
          else {
            tunel.setRequestProperty("Authorization", "Basic " + new String( mEncode64(userpass)));
          }

          tunel.setRequestProperty("tun", "0");
          if(ipv4 !=0 ) tunel.setRequestProperty("reconnect", String.format("%X",ipv4));

         // Log.i(getTag(), "Lb 3");


          // Connect to the server.
          tunel.req += "\r\n";
          sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
          sslSocket.setEnabledProtocols(sslSocket.getSupportedProtocols());
          sslSocket.setNeedClientAuth (false);
          sslSocket.setUseClientMode (true);
          sslSocket.setEnableSessionCreation (true);

          //Log.i(getTag(), TextUtils.join(":",sslSocket.getEnabledCipherSuites() ));
          //Log.i(getTag(), TextUtils.join(",",sslSocket.getEnabledProtocols() ));

          sslSocket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent event) {
              //Log.i(getTag(), "Lb 3a");
              connected = true;
            }
          });

          sslSocket.startHandshake();

          //Log.i(getTag(), "Lb 4");

          while(! connected )
          {
            Thread.sleep(200);
            //Log.i(getTag(), "Lb 5");
          }
          if(stop_thread) return false;
          //Log.i(getTag(), "Lb 6");
          byte[] b_packet = new byte[MAX_PACKET_SIZE+2];
          ByteBuffer s_packet = ByteBuffer.wrap(b_packet,0,MAX_PACKET_SIZE+2);
          s_packet.order(ByteOrder.LITTLE_ENDIAN);

          OutputStream s_out = sslSocket.getOutputStream();
          InputStream s_in = sslSocket.getInputStream();
          //Log.i(getTag(), "Lb 7");
          s_out.write(tunel.req.getBytes());

          Thread.sleep(1500);

          code = s_in.read(b_packet);
          //Log.i(getTag(), "Lb 9 "+ Integer.toString(code));
          if(code > 0) {
            tunel.req = new String(b_packet, 0, code);
            //Log.i(getTag(), tunel.req);
            String str = tunel.req.substring(9,12);
            //Log.i(getTag(), "|" + str);
            code = Integer.parseInt(str,10);
          }
          if( code != 200 ) {
            if(code == 401) {
              stop_thread = true;
              mService.mHandler.sendEmptyMessage(R.string.bad_pass);
              msg_sendet = true;
            }
            else if(code>=400) {
              stop_thread = true;
              mService.mHandler.sendEmptyMessage(code == 509 ? R.string.limover : R.string.bad_url);
              msg_sendet = true;
            }

            Log.e(getTag(), String.format("Connection error %d", code));
            return false;
          }
          //Log.i(getTag(), "Lb 10");
          // Protect the tunnel before connecting to avoid loopback.
          if (!mService.protect(socket)) {
            throw new IllegalStateException("Cannot protect the tunnel");
          }

          // Authenticate and configure the virtual network interface.
          iface = configure(tunel);

          //Log.i(getTag(), "Lb 11");

          // Packets to be sent are queued in this input stream.
          FileInputStream in = new FileInputStream(iface.getFileDescriptor());

          // Packets received need to be written to this output stream.
          FileOutputStream out = new FileOutputStream(iface.getFileDescriptor());

          s_packet.clear();

          RecvThread thr = new  RecvThread(s_in, out);
          ret = true;
          thr.start();

          while (socket.isConnected() && connected)
          {
            // Assume that we did not make any progress in this iteration.

            // Read the outgoing packet from the input stream.
            int length = in.read(b_packet,2,MAX_PACKET_SIZE);
            if(stop_thread) break;
            if (length > 0) {
              // Write the outgoing packet to the tunnel.

              s_packet.putShort(0,(short)length);
              s_out.write(b_packet,0,length+2);
              s_packet.clear();

              // There might be more outgoing packets.

              //Log.i(getTag(), String.format("out %d %d",length, out_counter));
              out_counter ++;
              out_bytes += length;
            }
          }

          Log.i(getTag(), "End... Disconnected");
        } catch (SocketException e) {
          Log.e(getTag(), "Cannot use socket", e);
          mService.iStatus = -3;
          mService.strStatus = mService.getString(R.string.cantconnect);
          mService.mUpdateTime = System.currentTimeMillis();
          connected = false;
        } catch (SSLHandshakeException e)
        {
          Log.e(getTag(), "Handshake error", e);
          connected = false;

          TLStried |= (1<<workTLS);

          workTLS = (workTLS + 1) & TriedMask;
          sslSocketFactory = null;
          if (TLStried == TriedMask)
          {
            Log.i(getTag(), "Handshake error " + TLStried + " workTLS =" + workTLS);
            stop_thread = true;
            mService.mHandler.sendEmptyMessage(R.string.handshake_failed);
            msg_sendet = true;
          }
        }
        catch (Exception e) {
          Log.e(getTag(), "Connection closed", e);
        }
        finally {
          connected = false;
          Log.i(getTag(), "Finaly... Close all");

          if (iface != null) {
            try {
              iface.close();
              iface = null;
            } catch (IOException e) {
              Log.e(getTag(), "Unable to close interface", e);
            }
          }
          if(sslSocket != null) {
            sslSocket.close();
            sslSocket = null;
          }
          if(socket != null ) {
            if(! socket.isClosed() ) {
              socket.shutdownInput();
              socket.shutdownOutput();
              socket.close();
            }
            socket = null;
          }

        }

        connected = false;
        return ret;
    }


    private ParcelFileDescriptor configure(HTTPReq tunel) throws IllegalArgumentException {
        // Configure a builder while parsing the parameters.
        int i = 0;
        int mtu;
        int preflen;
        String route;
        int routepref;
        long maskl;

        String t = tunel.getHeaderField("ip");
        if( t == null )
        {
            stop_thread = true;
            mService.mHandler.sendEmptyMessage(R.string.urlnotvpn);
            msg_sendet = true;
            throw new IllegalArgumentException("Can't get IP ");
        }
        ipv4 = Integer.parseInt(t,16);
        String ip = String.format("%d.%d.%d.%d", ipv4&0xFF, (ipv4>>8)&0xFF, (ipv4>>16)&0xFF, (ipv4>>24)&0xFF ) ;

        t = tunel.getHeaderField("mask");
        if( t == null )
        {
          preflen = 24;
          maskl = 1;
        }
        else
        {
          maskl = Long.parseLong(t,16);
          preflen = 32;
          if(maskl != 0) {
              while (0 == (maskl >> preflen)) {
                  preflen--;
              }
              preflen++;
          }
        }
        //Log.i(getTag(), "ip: " + ip + "/" + String.valueOf(preflen));

        VpnService.Builder builder = mService.new Builder();

        try {
          builder.setMtu(mMtu); i++;
          builder.addAddress(ip,  preflen);  i++;
          if(!LAN_only) builder.addRoute(mRoute, mRoutepr);

          i++;
          String dns = tunel.getHeaderField("dns");
          if( dns != null ){
              for(String str: dns.split("[, ]+")) {
                  //Log.i(getTag(), "dns:" + str);
                  builder.addDnsServer(str);
              }
                i++;
          }
          if (Build.VERSION.SDK_INT >= 29 /*Build.VERSION_CODES.LOLLIPOP*/) {
                builder.setMetered(false);
          }
          builder.setBlocking(true);
        } catch (NumberFormatException e) {
          throw new IllegalArgumentException("Bad parameter: " + String.valueOf(i) );
        }
        // Create a new interface using the builder and save the parameters.
        final ParcelFileDescriptor vpnInterface;
        builder.setSession(mServerName).setConfigureIntent(mConfigureIntent);
        //Log.i(getTag(), "conf 1");
        synchronized (mService) {
            vpnInterface = builder.establish();
            if(vpnInterface == null) {
                throw new IllegalArgumentException("Cant build TUN object\n" );
            }
            if (mOnEstablishListener != null) {
                mOnEstablishListener.onEstablish(vpnInterface);
            }
        }
        //Log.i(getTag(), "New interface: " + vpnInterface.toString() );
        return vpnInterface;
    }

    private final String getTag() {
        return "smallsrvvpn_log" + "[" + mConnectionId + "]";
    }
}
