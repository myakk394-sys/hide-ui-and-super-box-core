import paramiko

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
        
        # Run list-peers and print stdout + stderr
        stdin, stdout, stderr = ssh.exec_command("cd /var/lib/super_box && ./super_box list-peers")
        print("\n=== Registered Peers on VPS ===")
        print("STDOUT:")
        print(stdout.read().decode('utf-8', errors='replace').strip())
        print("STDERR:")
        print(stderr.read().decode('utf-8', errors='replace').strip())
        
    except Exception as e:
        print(f"[-] Failed: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    main()
