import paramiko
import time

def main():
    ip = "YOUR_VPS_IP"
    username = "root"
    password = "YOUR_SSH_PASSWORD"

    print(f"[*] Connecting to remote server {username}@{ip} via SSH...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(ip, username=username, password=password, timeout=15)
        print("[SUCCESS] Connected!")
        
        # 1. Force kill all running super_box processes
        print("[*] Force killing all existing super_box processes on the VPS...")
        stdin, stdout, stderr = ssh.exec_command("killall -9 super_box")
        stdout.channel.recv_exit_status() # block until completed
        
        print("[*] Waiting 2 seconds for port releases...")
        time.sleep(2.0)
        
        # 2. Check if any processes are still alive
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep super_box | grep -v grep")
        out = stdout.read().decode().strip()
        if out:
            print(f"[!] Warning: Processes are still running: {out}")
            # Try kill -9 by PID
            for line in out.splitlines():
                parts = line.split()
                if len(parts) > 1:
                    pid = parts[1]
                    print(f"[*] Force killing PID {pid}...")
                    ssh.exec_command(f"kill -9 {pid}").channel.recv_exit_status()
        else:
            print("[SUCCESS] All old server processes successfully terminated!")

        # 3. Launch the NEW compiled release binary
        print("[*] Launching the NEW compiled release binary super_box on port 8443...")
        # Path to release: /var/lib/super_box/target/release/super_box
        launch_cmd = "nohup bash -c 'cd /var/lib/super_box && ./target/release/super_box server' > /var/log/super_box.log 2>&1 &"
        ssh.exec_command(launch_cmd)
        time.sleep(2.0)
        
        # 4. Verify running processes and ports
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep super_box | grep -v grep")
        print("\n=== Active Processes ===")
        print(stdout.read().decode().strip())
        
        stdin, stdout, stderr = ssh.exec_command("ss -tlnp | grep -E '8443|8082'")
        print("\n=== Active Ports (8443 / 8082) ===")
        print(stdout.read().decode().strip())
        
    except Exception as e:
        print(f"[-] Failed: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
