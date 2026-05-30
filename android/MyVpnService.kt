package org.hidekey.core.superbox

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Android VpnService implementation for the Hidekey VPN client.
 *
 * This service handles establishing the Android local TUN adapter,
 * launching the native JNI worker thread, and proxying TCP/UDP traffic.
 */
class MyVpnService : VpnService(), Runnable {

    companion object {
        private const val TAG = "HidekeyVpnService"
        
        // Load our native JNI Rust library on startup
        init {
            System.loadLibrary("super_box")
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    
    // Paste your subscription / peer connection URL here
    private val configUrl = "hidekey://YOUR_PEER_MASTER_KEY@YOUR_SERVER_IP:8443"

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand: Starting Hidekey VPN service...")
        
        // Spawn a thread to initialize the interface and Rust network loop
        if (vpnThread == null || !vpnThread!!.isAlive) {
            vpnThread = Thread(this, "HidekeyVPNThread")
            vpnThread!!.start()
        }
        
        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy: Stopping Hidekey VPN service...")
        stopVpn()
        super.onDestroy()
    }

    override fun run() {
        try {
            Log.i(TAG, "Thread run: Creating virtual adapter...")
            
            // 1. Establish the TUN Interface
            val builder = Builder()
            builder.setMtu(9000)
            builder.addAddress("10.0.0.2", 24)
            builder.addRoute("0.0.0.0", 0)  // Intercept all outgoing IPv4 traffic
            builder.addDnsServer("8.8.8.8") // Force Windows-like target DNS server
            builder.setSession("Hidekey-SuperBox")
            
            // Configure the adapter
            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface (null)")
                return
            }

            val fd = vpnInterface!!.fd
            Log.i(TAG, "TUN interface active on File Descriptor: $fd")

            // 2. Call Native Rust JNI interface to start tunneling
            val result = startTunnel(fd, configUrl)
            if (!result) {
                Log.e(TAG, "JNI startTunnel returned failure!")
                stopVpn()
                return
            }

            Log.i(TAG, "Hidekey core active and running in native worker thread! ✓")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in VPN service loop: ${e.message}", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing vpn interface: ${e.message}")
        }
        vpnInterface = null
        vpnThread = null
        Log.i(TAG, "VPN service fully stopped.")
    }

    /**
     * Declares the native JNI method implemented in `jni_wrapper.rs`.
     */
    private external fun startTunnel(tunFd: Int, configUrl: String): Boolean
}
