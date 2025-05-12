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

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.util.Pair;
import android.widget.Toast;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class SmallSrvVpnService extends VpnService implements Handler.Callback {
    private static final String TAG = SmallSrvVpnService.class.getSimpleName();

    public static final String ACTION_CONNECT = "com.smallsrv.vpn.START";
    public static final String ACTION_DISCONNECT = "com.smallsrv.vpn.STOP";

    public Handler mHandler;

    private static class Connection extends Pair<Thread, ParcelFileDescriptor> {
        public Connection(Thread thread, ParcelFileDescriptor pfd) {
            super(thread, pfd);
        }
    }

    private final AtomicReference<Thread> mConnectingThread = new AtomicReference<>();
    private final AtomicReference<Connection> mConnection = new AtomicReference<>();

    private AtomicInteger mNextConnectionId = new AtomicInteger(1);

    private PendingIntent mConfigureIntent;

    public SmallSrvVpnConnection mConn;

    public String strStatus;
    public int iStatus;
    public long mUpdateTime;
    public String VrongSert;
    public String Issuer;
    public long hashSign;
    public long hashPkey;

    static private  SmallSrvVpnService  mInstance;
    static public SmallSrvVpnService getInstance(){ return mInstance; }

    @Override
    public void onCreate() {
        mInstance = this;
        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = new Handler(this);
        }
        //Log.i("smallsrvvpn_log_serv", "Service Create" );

        // Create the intent to "configure" the connection (just start SmallSrvVpnClient).
        mConfigureIntent = PendingIntent.getActivity(this,  0, new Intent(this, SmallSrvVpnClient.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        //Log.i("smallsrvvpn_log_serv", "Command" );
        if (intent != null && ACTION_DISCONNECT.equals(intent.getAction())) {
            disconnect();
            return START_NOT_STICKY;
        } else {
            //Log.i("smallsrvvpn_log_serv", "Connect" );
            connect();
            return START_STICKY;
        }
    }

    @Override
    public void onDestroy() {
        disconnect();
    }

    @Override
    public boolean handleMessage(Message message) {
        Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        try {
            if (message.what != R.string.disconnected) {
                updateForegroundNotification(message.what);
            } else stopForeground(true);
        }
        catch (Exception ex)
        {
            Log.e("smallsrvvpn_log_serv", "Notification error");
        }

        if(iStatus >= 0) {
            strStatus = getString(message.what);
            mUpdateTime = System.currentTimeMillis();
        }

        if(R.string.connected != message.what && iStatus > 0 ) iStatus = 0;
        return true;
    }

    private void connect() {
        // Become a foreground service. Background services can be VPN services too, but they can
        // be killed by background check before getting a chance to receive onRevoke().

        // Extract information from the shared preferences.
        final SharedPreferences prefs = getSharedPreferences(SmallSrvVpnClient.Prefs.NAME, MODE_PRIVATE);
        final String server = prefs.getString(SmallSrvVpnClient.Prefs.SERVER_ADDRESS, "");
        final String secret = prefs.getString(SmallSrvVpnClient.Prefs.SHARED_SECRET, "");
        final String user = prefs.getString(SmallSrvVpnClient.Prefs.USER_NAME, "");
        final boolean lo = prefs.getBoolean(SmallSrvVpnClient.Prefs.LAN_ONLY, false);
        final Set<String> packages =
                prefs.getStringSet(SmallSrvVpnClient.Prefs.PACKAGES, Collections.emptySet());
        final int port = prefs.getInt(SmallSrvVpnClient.Prefs.SERVER_PORT, 0);
        try {
            //Log.i("smallsrvvpn_log_serv", "Connect 1" );
            mConn = new SmallSrvVpnConnection(
                    this, mNextConnectionId.getAndIncrement(), server, //port,
                    user,
                    secret, lo
            );
            //Log.i("smallsrvvpn_log_serv", "Connect 2" );
            updateForegroundNotification(R.string.connecting);
            mHandler.sendEmptyMessage(R.string.connecting);
            //Log.i("smallsrvvpn_log_serv", "Connect 3" );

            startConnection(mConn);
            //Log.i("smallsrvvpn_log_serv", "Connect 4" );
        } catch (IllegalArgumentException e) {
            Log.i("smallsrvvpn_log" , "Bad parametr server/key");
            mHandler.sendEmptyMessage(R.string.badserverkey);
        }
    }

    private void startConnection(final SmallSrvVpnConnection connection) {
        // Replace any existing connecting thread with the  new one.
        final Thread thread = new Thread(connection, "SmallSrvVpnThread");
        setConnectingThread(thread);

        //Log.i("smallsrvvpn_log_serv", "Connect 5" );
        // Handler to mark as connected once onEstablish is called.
        connection.setConfigureIntent(mConfigureIntent);
        //Log.i("smallsrvvpn_log_serv", "Connect 6" );
        connection.setOnEstablishListener(tunInterface -> {
            mHandler.sendEmptyMessage(R.string.connected);
            mConnectingThread.compareAndSet(thread, null);
            setConnection(new Connection(thread, tunInterface));
            iStatus = 1;
            strStatus = getString(R.string.connected);
            mUpdateTime = System.currentTimeMillis();
            Log.i("smallsrvvpn_log_serv", "Connect established" );
        });
        //Log.i("smallsrvvpn_log_serv", "Connect 7" );
        thread.start();
        //Log.i("smallsrvvpn_log_serv", "Connect 8" );
    }

    private void setConnectingThread(final Thread thread) {
        final Thread oldThread = mConnectingThread.getAndSet(thread);
        if (oldThread != null) {
            oldThread.interrupt();
        }
    }

    private void setConnection(final Connection connection) {
        final Connection oldConnection = mConnection.getAndSet(connection);
        if (oldConnection != null) {
            try {
                oldConnection.first.interrupt();
                oldConnection.second.close();
            } catch (IOException e) {
                Log.e(TAG, "Closing VPN interface", e);
            }
        }
    }

    private void disconnect() {
        if(mConn != null) {
            mConn.stop_thread = true;
            mConn.connected = false;
        }
        iStatus = 0;
        strStatus = getString(R.string.disconnected);
        mUpdateTime = System.currentTimeMillis();
        mHandler.sendEmptyMessage(R.string.disconnected);

        setConnectingThread(null);
        setConnection(null);
        stopForeground(true);
        mConn = null;
    }

    private void updateForegroundNotification(final int message) {
        final String NOTIFICATION_CHANNEL_ID = "SmallSrvVpn";
        NotificationManager mNotificationManager = (NotificationManager) getSystemService(
                NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 /*Build.VERSION_CODES.LOLLIPOP*/) {
            try {
                mNotificationManager.createNotificationChannel(new NotificationChannel(
                    NOTIFICATION_CHANNEL_ID, NOTIFICATION_CHANNEL_ID,
                    NotificationManager.IMPORTANCE_DEFAULT));

                Notification notification = new Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
                        .setSmallIcon(R.drawable.ic_vpn)
                        .setContentText(getString(message))
                        .setContentIntent(mConfigureIntent)
                        .build();
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) { //34
                          startForeground(1, notification);
                } else {
                    startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
                }
            } catch (Exception e) {
                Log.e(TAG, String.format("Error update Notification %u", message), e);
            }
        }
        else
        {
            Notification notification = new Notification();
            startForeground(1, notification);
        }
    }
}
