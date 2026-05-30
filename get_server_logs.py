import paramiko
import sys

def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

    ip = "YOUR_VPS_IP"
    username = "root"
    password = "YOUR_SSH_PASSWORD"

    print(f"[*] Connecting to remote server {username}@{ip} via SSH to read logs...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(ip, username=username, password=password, timeout=15)
        print("[SUCCESS] Connected!")
        
        # Read the last 150 lines of the superbox service journal logs
        stdin, stdout, stderr = ssh.exec_command("journalctl -u superbox -n 150 --no-pager")
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        
        with open("vps_server.log", "w", encoding="utf-8") as f:
            f.write(out)
            if err:
                f.write("\n=== STDERR ===\n")
                f.write(err)
        
        print("[OK] Server logs successfully saved to vps_server.log!")
            
    except Exception as e:
        print(f"[-] Failed: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()

