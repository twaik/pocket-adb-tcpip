package dev.twaik.adbtcpip;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

import java.text.SimpleDateFormat;
import java.util.Locale;

public class MainActivity extends Activity {

    private static final String ACTION_USB_PERMISSION = "dev.twaik.adbtcpip.USB_PERMISSION";

    private UsbManager usbManager;
    private TextView deviceText;
    private EditText portInput;
    private Button connectButton;
    private TextView logText;
    private ScrollView logScroll;

    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());

    private UsbDevice selectedDevice;
    private boolean pendingConnect;

    private final BroadcastReceiver usbReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (ACTION_USB_PERMISSION.equals(action)) {
                UsbDevice device = getUsbDeviceExtra(intent);
                boolean granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false);
                if (granted && device != null) {
                    selectedDevice = device;
                    if (pendingConnect) {
                        pendingConnect = false;
                        startConnectFlow(device);
                    }
                } else {
                    pendingConnect = false;
                    appendLog("USB permission denied");
                }
            } else if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)
                    || UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
                refreshDeviceList();
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        View root = findViewById(R.id.root);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setDecorFitsSystemWindows(false);
        }
        applySystemBarInsets(root);

        usbManager = (UsbManager) getSystemService(Context.USB_SERVICE);
        deviceText = findViewById(R.id.deviceText);
        portInput = findViewById(R.id.portInput);
        connectButton = findViewById(R.id.connectButton);
        logText = findViewById(R.id.logText);
        logScroll = findViewById(R.id.logScroll);

        connectButton.setOnClickListener(v -> onConnectClicked());

        IntentFilter filter = new IntentFilter();
        filter.addAction(ACTION_USB_PERMISSION);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(usbReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(usbReceiver, filter);
        }

        refreshDeviceList();
    }

    /** Edge-to-edge is enforced on API 35+; pad the root by the status/nav bar insets on top of its own XML padding. */
    private void applySystemBarInsets(View root) {
        int baseLeft = root.getPaddingLeft();
        int baseTop = root.getPaddingTop();
        int baseRight = root.getPaddingRight();
        int baseBottom = root.getPaddingBottom();
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(
                    baseLeft + insets.getSystemWindowInsetLeft(),
                    baseTop + insets.getSystemWindowInsetTop(),
                    baseRight + insets.getSystemWindowInsetRight(),
                    baseBottom + insets.getSystemWindowInsetBottom());
            return insets;
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(usbReceiver);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        refreshDeviceList();
    }

    private void refreshDeviceList() {
        UsbDevice found = null;
        for (UsbDevice device : usbManager.getDeviceList().values()) {
            if (AdbProtocol.UsbTransport.findAdbEndpoints(device) != null) {
                found = device;
                break;
            }
        }
        selectedDevice = found;
        if (found == null) {
            deviceText.setText("No USB-debuggable device found.\nConnect it via an OTG cable and enable \"USB debugging\" in Developer options.");
            connectButton.setEnabled(false);
        } else {
            String name = found.getProductName() != null ? found.getProductName() : found.getDeviceName();
            String manufacturer = found.getManufacturerName() != null ? found.getManufacturerName() : "?";
            deviceText.setText("Found: " + name + " (" + manufacturer + ")");
            connectButton.setEnabled(true);
        }
    }

    private void onConnectClicked() {
        UsbDevice device = selectedDevice;
        if (device == null) {
            appendLog("No ADB device connected");
            return;
        }

        if (usbManager.hasPermission(device)) {
            startConnectFlow(device);
        } else {
            pendingConnect = true;
            int flags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ? PendingIntent.FLAG_MUTABLE : 0;
            PendingIntent permissionIntent = PendingIntent.getBroadcast(
                    this, 0, new Intent(ACTION_USB_PERMISSION).setPackage(getPackageName()), flags);
            usbManager.requestPermission(device, permissionIntent);
        }
    }

    private void startConnectFlow(UsbDevice device) {
        Integer port = parsePort(portInput.getText().toString());
        if (port == null) {
            appendLog("Invalid port");
            return;
        }

        connectButton.setEnabled(false);
        String name = device.getProductName() != null ? device.getProductName() : device.getDeviceName();
        appendLog("Connecting to " + name + "...");

        new Thread(() -> {
            String result;
            try {
                result = connectAndEnableTcpip(device, port);
            } catch (AdbProtocol.AdbAuthException e) {
                result = null;
                runOnUiThread(() -> {
                    appendLog("Device rejected the authorization key.");
                    appendLog("Check the device's screen: it should show an \"Allow USB debugging?\" prompt - confirm it and try again.");
                });
            } catch (Exception e) {
                result = null;
                String message = e.getMessage() != null ? e.getMessage() : e.toString();
                runOnUiThread(() -> appendLog("Error: " + message));
            }
            if (result != null) {
                String finalResult = result;
                runOnUiThread(() -> appendLog(finalResult));
            }
            runOnUiThread(() -> connectButton.setEnabled(true));
        }).start();
    }

    private Integer parsePort(String text) {
        try {
            int port = Integer.parseInt(text.trim());
            return port >= 1 && port <= 65535 ? port : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private String connectAndEnableTcpip(UsbDevice device, int port) throws Exception {
        AdbProtocol.UsbTransport.Endpoints endpoints = AdbProtocol.UsbTransport.findAdbEndpoints(device);
        if (endpoints == null) {
            return "Device has no ADB interface (check that \"USB debugging\" is enabled)";
        }
        UsbDeviceConnection usbConnection = usbManager.openDevice(device);
        if (usbConnection == null) {
            return "Failed to open USB connection";
        }

        AdbProtocol.UsbTransport transport = new AdbProtocol.UsbTransport(usbConnection, endpoints);
        try {
            AdbProtocol.KeyPair keyPair = AdbProtocol.KeyPair.readOrGenerate(getFilesDir());
            AdbProtocol.Connection connection = AdbProtocol.Connection.connect(transport, keyPair);
            try {
                String response = connection.openAndRead("tcpip:" + port).trim();
                if (!response.isEmpty()) {
                    return "Done: " + response;
                }
                return "Sent tcpip:" + port + "; the device closed the USB connection (expected - adbd is restarting in TCP mode).";
            } finally {
                connection.close();
            }
        } finally {
            transport.close();
        }
    }

    private void appendLog(String message) {
        String line = "[" + timeFormat.format(System.currentTimeMillis()) + "] " + message + "\n";
        logText.append(line);
        logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
    }

    private static UsbDevice getUsbDeviceExtra(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice.class);
        } else {
            return intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
        }
    }
}
