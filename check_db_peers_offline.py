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
        
        # Stop service
        print("[*] Stopping superbox service...")
        stdin, stdout, stderr = ssh.exec_command("sudo systemctl stop superbox")
        stdout.read() # block until completed
        time.sleep(1.0)
        
        # Run list-peers
        print("[*] Querying peers offline...")
        stdin, stdout, stderr = ssh.exec_command("cd /var/lib/super_box && ./super_box list-peers")
        out = stdout.read().decode('utf-8', errors='replace').strip()
        err = stderr.read().decode('utf-8', errors='replace').strip()
        
        print("\n=== Registered Peers ===")
        print(out)
        if err:
            print("Errors:", err)
            
        # Restart service
        print("\n[*] Starting superbox service back up...")
        stdin, stdout, stderr = ssh.exec_command("sudo systemctl start superbox")
        stdout.read() # block until completed
        
    except Exception as e:
        print(f"[-] Failed: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
