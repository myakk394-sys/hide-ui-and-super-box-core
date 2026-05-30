import paramiko
import sys

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
        
        # Get last 100 log lines from journalctl for superbox service
        stdin, stdout, stderr = ssh.exec_command("sudo journalctl -u superbox -n 100 --no-pager")
        logs = stdout.read().decode('utf-8', errors='replace')
        
        with open("recent_vps.log", "w", encoding="utf-8") as f:
            f.write(logs)
            
        print("[SUCCESS] Logs successfully saved to recent_vps.log")
        
    except Exception as e:
        print(f"[-] Failed: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
