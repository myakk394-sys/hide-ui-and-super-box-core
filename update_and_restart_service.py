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
        
        # 1. Stop the systemd service if running
        print("[*] Stopping superbox systemd service...")
        stdin, stdout, stderr = ssh.exec_command("sudo systemctl stop superbox")
        stdout.channel.recv_exit_status()
        
        # 2. Force kill all running processes to release port/db locks
        print("[*] Terminating any remaining python3 processes at /var/lib/super_box/...")
        stdin, stdout, stderr = ssh.exec_command("sudo pkill -f /var/lib/super_box/python3")
        stdout.channel.recv_exit_status()
        
        print("[*] Waiting for socket/port release...")
        time.sleep(2.0)
        
        # 3. Copy the compiled release binary to the target location used by systemd
        print("[*] Copying newly compiled binary to /var/lib/super_box/python3...")
        stdin, stdout, stderr = ssh.exec_command("cp /var/lib/super_box/target/release/super_box /var/lib/super_box/python3")
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            err = stderr.read().decode().strip()
            print(f"[-] Failed to copy binary: {err}")
            return
            
        print("[SUCCESS] Binary updated successfully!")
        
        # 4. Start the systemd service
        print("[*] Starting superbox systemd service...")
        stdin, stdout, stderr = ssh.exec_command("sudo systemctl start superbox")
        stdout.channel.recv_exit_status()
        
        print("[*] Waiting 3 seconds for service startup...")
        time.sleep(3.0)
        
        # 5. Check processes and ports
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep python3 | grep -v grep")
        print("\n=== Active Processes on VPS ===")
        print(stdout.read().decode().strip())
        
        # Determine the port currently configured in database
        stdin, stdout, stderr = ssh.exec_command("cd /var/lib/super_box && ./python3 server --help 2>&1")
        # Just check netstat to see what ports are listening
        stdin, stdout, stderr = ssh.exec_command("ss -tlnp | grep python3")
        print("\n=== Active Listening Ports ===")
        print(stdout.read().decode().strip())
        
    except Exception as e:
        print(f"[-] Failed: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
