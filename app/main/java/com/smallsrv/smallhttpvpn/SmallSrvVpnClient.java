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
 * Contact addresses for Email: support@smallsrv.com
 */

package com.smallsrv.smallhttpvpn;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;

import android.os.Looper;
import android.os.Message;
import android.text.method.PasswordTransformationMethod;
import android.text.method.SingleLineTransformationMethod;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

public class SmallSrvVpnClient extends Activity {
    public interface Prefs {
        String NAME = "connection";
        String SERVER_ADDRESS = "server.address";
        String SERVER_PORT = "server.port";
        String USER_NAME = "user.name";
        String SHARED_SECRET = "shared.secret";
        String LAN_ONLY="lan_only";
        String ALLOW = "allow";
        String PACKAGES = "packages";
    }

    CheckBox showPas;
    CheckBox LANonly;
    TextView mStatus;
    public Timer mTimer;
    public TimerTask mTimerTask;
    public long  mUpdateTime = 0;
    public long in_kbytes = 0;
    public long out_kbytes = 0;

    public boolean isInvisible;

    TextView cert;
    Button buttonTrast;

    private Spinner listbox;
    protected Handler handler;

    public List<String> lServers;

    SharedPreferences prefs;
    private Menu mmenu;



    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.form);

        final TextView serverAddress = findViewById(R.id.address);
        final TextView userName = findViewById(R.id.uname);
        final TextView sharedSecret = findViewById(R.id.secret);
        final Button ConBut = findViewById(R.id.connect);
        cert = (TextView) findViewById(R.id.cert);
        buttonTrast = (Button) findViewById(R.id.trast);

        showPas = findViewById(R.id.show_pass);
        LANonly = findViewById(R.id.lan);
        mStatus = findViewById(R.id.app_status);
        prefs = getSharedPreferences(Prefs.NAME, MODE_PRIVATE);
        serverAddress.setText(prefs.getString(Prefs.SERVER_ADDRESS, ""));
        userName.setText(prefs.getString(Prefs.USER_NAME, ""));
        sharedSecret.setText(prefs.getString(Prefs.SHARED_SECRET, ""));

        ConBut.setOnClickListener(v -> {
            String serv_address = serverAddress.getText().toString();
            String t;
            String cfg =getCfgByServer(serv_address);
            if (cfg == null) {
                //mStatus.setTextColor(0xC0000);
                mStatus.setText(R.string.badserverkey);
                mUpdateTime = System.currentTimeMillis();
                return;
            }
            mStatus.setText("Conecting..");
            mUpdateTime = System.currentTimeMillis();

            t = String.format("%s;%s;%s", serv_address, userName.getText().toString(),
                              sharedSecret.getText().toString());

            prefs.edit()
                    .putString(Prefs.SERVER_ADDRESS, serv_address)
                    .putString(Prefs.USER_NAME, userName.getText().toString())
                    .putString(Prefs.SHARED_SECRET, sharedSecret.getText().toString())
                    .putBoolean(Prefs.LAN_ONLY, LANonly.isChecked())
                    .putString("c_" + cfg, t)
                    .commit();
            int i = lServers.indexOf(cfg);
            if( i<0 ){
              lServers.add(cfg);
              i = lServers.indexOf(cfg);
            }
            if(i>=0)listbox.setSelection(i);
                                  Intent intent = VpnService.prepare(SmallSrvVpnClient.this);
            if (intent != null) {
                startActivityForResult(intent, 0);
            } else {
                onActivityResult(0, RESULT_OK, null);
            }
        });
        findViewById(R.id.disconnect).setOnClickListener(v -> {
            startService(getServiceIntent().setAction(SmallSrvVpnService.ACTION_DISCONNECT));
        });

        buttonTrast.setOnClickListener(v -> {
            SmallSrvVpnService mService = SmallSrvVpnService.getInstance();

            if (mService != null) {
                String sn = mService.VrongSert;
                final SharedPreferences prefs2 = getSharedPreferences("sert", MODE_PRIVATE);
                sn = sn.replaceAll("[^a-zA-Z0-9]+", "_");
                prefs2.edit().putLong(sn, mService.hashPkey).commit();

                buttonTrast.setVisibility(View.INVISIBLE);
                cert.setVisibility(View.INVISIBLE);
                ConBut.performClick();
            }
        });

        showPas.setOnClickListener(v -> {
            if (showPas.isChecked()) {
                sharedSecret.setTransformationMethod(new SingleLineTransformationMethod());
            } else {
                sharedSecret.setTransformationMethod(new PasswordTransformationMethod());
            }
        });
        try{
            lServers = new ArrayList<String>();
            Map<String, ?> prf = prefs.getAll();
            for (String key : prf.keySet()) {
                if( key.indexOf("c_") == 0) {
                    lServers.add(key.substring(2));
                }
            }
            if(lServers.size()<=0) {
                lServers.add("");
            }

            listbox =(Spinner) findViewById(R.id.lb1);

            ArrayAdapter aa=new ArrayAdapter(this,android.R.layout.simple_spinner_dropdown_item,lServers);
            listbox.setAdapter(aa);
            String server_name = prefs.getString(Prefs.SERVER_ADDRESS, "");
            if (! server_name.isEmpty()) {
                String cfg = getCfgByServer(server_name);
                if(cfg !=null ){
                    int i=lServers.indexOf(cfg);
                    if(i>=0) listbox.setSelection(i);
                }
            }


            listbox.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener()
            {
                @Override
                public void onItemSelected(AdapterView<?> parent, View view, int position, long id)
                {
                    if(position>=0)
                    {
                        String s=lServers.get(position);
                        try {
                            String t = prefs.getString("c_"+s, "");
                            if (!t.equals("")) {
                                String[] tt = t.split(";", 4);

                                serverAddress.setText(tt[0]);
                                userName.setText(tt[1]);
                                sharedSecret.setText(tt[2]);
                            }
                        }catch (Exception ex)
                        {
                            Log.e("smallsrvvpn_log_serv", "Load cfg error");
                        }
                    }
                }
                @Override
                public void onNothingSelected(AdapterView<?> parent) {
                    // Another interface callback
                }

            });

        }catch (Exception ex)
        {
            Log.e("smallsrvvpn_log_serv", "List box error ");
        }

        handler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {
                SmallSrvVpnService mService = SmallSrvVpnService.getInstance();

                if (mUpdateTime < mService.mUpdateTime) {
                    mStatus.setText(mService.strStatus);
                    mUpdateTime = mService.mUpdateTime;
                }

                if(mService.iStatus == 1 && mService.mConn != null)
                {
                    long i = mService.mConn.in_bytes >> 10;
                    long o = mService.mConn.out_bytes >> 10;
                    if(in_kbytes != i || out_kbytes != o ) {
                        in_kbytes = i;
                        out_kbytes = o;
                        mStatus.setText(String.format("In: %dKb Out: %dKb", i, o));
                    }
                }

                if (mService.iStatus == -1 && mService.VrongSert != null) {

                    cert.setVisibility(View.VISIBLE);
                    buttonTrast.setVisibility(View.VISIBLE);
                    cert.setText(mService.VrongSert + " \r\nIssuer: " + mService.Issuer);

                    mService.iStatus = 0;

                    mStatus.setText(R.string.unknown_sert);
                    mUpdateTime = mService.mUpdateTime;
                }
            }

        };

    }

    String getCfgByServer(String serv_address)
    {
        int i = serv_address.indexOf('/');
        if(i > 0)
          return  serv_address.substring(0, i).replaceAll("[^a-zA-Z0-9.]+", "_");
        return  null;
    }

    @Override
    protected void onResume() {
        super.onResume();
        isInvisible = false;
        if(mTimer == null) {
            StartTimer();
        }
    }

    public void  StartTimer()
    {
        isInvisible = false;
        mTimer = new Timer();
        mTimerTask = new TimerTask() {
            public void run() {
                if((!isInvisible)) {
                    SmallSrvVpnService mService = SmallSrvVpnService.getInstance();

                    if(mService != null)
                    {
                        handler.sendEmptyMessage(0);
                    }
                }
            }
        };

        mTimer.schedule(mTimerTask , 1000, 2000);

    }
    public void StopTimer()
    {
        isInvisible = true;
        if(mTimer != null) {
            mTimer.cancel();
            mTimer.purge();
            mTimer = null;
            mTimerTask = null;
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        StopTimer();

    }
    @Override
    protected void onStop() {
        super.onStop();
        StopTimer();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.mmenu, menu);

        mmenu=menu;
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement

        if(id == R.id.rms)
        {
            SharedPreferences.Editor editor = prefs.edit();
            for(String nm: lServers) {
                editor.remove("c_"+nm);
                Log.i("smallsrvvpn_log_serv", "remove server key: " + nm );
            }
            lServers.clear();
            editor.commit();
            return true;
        }
        if(id == R.id.rmc)
        {
            Log.i("smallsrvvpn_log_serv", "remove sert" );
            final SharedPreferences prefs2 = getSharedPreferences("sert", MODE_PRIVATE);
            SharedPreferences.Editor editor = prefs2.edit();
            Map<String, ?> prf = prefs2.getAll();
            for (String key : prf.keySet()) {
                Log.i("smallsrvvpn_log_serv", "remove sert key: " + key );
                editor.remove(key);
            }
            editor.commit();
            return true;
        }
        if(id == R.id.rm_current)
        {
            SharedPreferences.Editor editor = prefs.edit();
            int i = listbox.getSelectedItemPosition();
            if(i>=0 && i<lServers.size()) {
                String nm = lServers.get(i);
                if(nm!=null) {
                    editor.remove("c_" + nm);
                    lServers.remove(i);
                    editor.commit();
                }
            }
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (result == RESULT_OK) {
            startService(getServiceIntent().setAction(SmallSrvVpnService.ACTION_CONNECT));
        }
    }

    private Intent getServiceIntent() {
        return new Intent(this, SmallSrvVpnService.class);
    }
}
