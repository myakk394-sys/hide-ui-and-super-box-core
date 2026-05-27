import os
import sys
import paramiko

def main():
    ip = os.environ.get("SERVER_IP", "YOUR_SERVER_IP")
    username = os.environ.get("SERVER_USER", "root")
    password = os.environ.get("SERVER_PASS", "YOUR_SERVER_PASSWORD")

    print(f"[*] Connecting to remote server {username}@{ip} via SSH...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(ip, username=username, password=password, timeout=15)
    except Exception as e:
        print(f"[-] SSH Connection failed: {e}")
        return

    print("[SUCCESS] Connected!")

    # 1. Install musl-tools on Ubuntu VPS to get musl-gcc
    print("[*] Installing musl-tools on remote VPS (required for C-dependencies like ring)...")
    stdin, stdout, stderr = ssh.exec_command("sudo apt-get update -y && sudo apt-get install -y musl-tools")
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[-] Warning/Error installing musl-tools: {stderr.read().decode()}")
    else:
        print("[SUCCESS] musl-tools successfully installed!")

    # 2. Add the target to rustup
    print("[*] Adding x86_64-unknown-linux-musl target to Rustup...")
    stdin, stdout, stderr = ssh.exec_command("/root/.cargo/bin/rustup target add x86_64-unknown-linux-musl")
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[-] Failed to add rustup target: {stderr.read().decode()}")
        ssh.close()
        return
    print("[SUCCESS] Target added successfully!")

    # 3. Compile the static binary
    print("[*] Compiling static release binary for x86_64-unknown-linux-musl on remote server...")
    print("[*] (This might take 1-2 minutes because it builds C dependencies statically)...")
    
    build_cmd = "bash -c 'source $HOME/.cargo/env && cd /var/lib/super_box && cargo build --release --target x86_64-unknown-linux-musl'"
    stdin, stdout, stderr = ssh.exec_command(build_cmd)
    
    # Wait for the command to finish
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"[-] Build FAILED on VPS: {stderr.read().decode()}")
        ssh.close()
        return
    print("[SUCCESS] Static musl binary compiled successfully on remote VPS!")

    # 4. Create the local destination directory
    local_dir = r"c:\Users\User\Desktop\super box\target\x86_64-unknown-linux-musl\release"
    print(f"[*] Creating local target directory: {local_dir}")
    os.makedirs(local_dir, exist_ok=True)

    local_path = os.path.join(local_dir, "super_box")

    # 5. Download the compiled static binary back to local PC via SFTP
    print("[*] Downloading the compiled static binary via SFTP...")
    sftp = ssh.open_sftp()
    remote_path = "/var/lib/super_box/target/x86_64-unknown-linux-musl/release/super_box"
    
    try:
        sftp.get(remote_path, local_path)
        print(f"[SUCCESS] Downloaded successfully!")
        print(f"👉 Local static binary location: {local_path}")
        
        # Make the local binary executable (for wsl or future copies) and show stats
        size = os.path.getsize(local_path)
        print(f"📦 Static Binary Size: {size / (1024*1024):.2f} MB")
    except Exception as e:
        print(f"[-] SFTP Download failed: {e}")
    finally:
        sftp.close()
        ssh.close()

if __name__ == "__main__":
    main()
