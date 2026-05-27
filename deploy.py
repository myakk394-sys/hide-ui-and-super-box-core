import sys
import paramiko

def deploy():
    if len(sys.argv) < 4:
        print("Usage: python deploy.py <ip> <username> <password>")
        return

    ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    print(f"[*] Connecting via SSH to {username}@{ip}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(ip, username=username, password=password, timeout=15)
    except Exception as e:
        print(f"ERROR: SSH connection failed: {e}")
        return

    print("[SUCCESS] Connected successfully!")

    # 1. Update APT and install dependencies
    print("[*] Installing required Ubuntu packages (curl, build-essential, git)...")
    commands = [
        "sudo apt-get update -y",
        "sudo apt-get install -y curl build-essential git gcc make pkg-config libssl-dev"
    ]
    for cmd in commands:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            err = stderr.read().decode().strip()
            print(f"[!] Warning on command '{cmd}': {err}")

    # 2. Check if Rust is installed, if not, install it
    print("[*] Checking Rust toolchain...")
    stdin, stdout, stderr = ssh.exec_command("rustc --version")
    if stdout.channel.recv_exit_status() != 0:
        print("[*] Rust not found. Installing Rustup toolchain on server...")
        stdin_inst, stdout_inst, stderr_inst = ssh.exec_command("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")
        exit_status = stdout_inst.channel.recv_exit_status()
        if exit_status != 0:
            err = stderr_inst.read().decode().strip()
            print(f"[-] Rustup installation failed: {err}")
            return
        print("[SUCCESS] Rustup toolchain installed successfully!")
        path_cmd = "source $HOME/.cargo/env"
    else:
        print("[SUCCESS] Rust is already installed!")
        path_cmd = "true"

    # 3. Setup the Super Box directory
    print("[*] Creating /var/lib/super_box directory...")
    stdin_dir, stdout_dir, stderr_dir = ssh.exec_command("sudo mkdir -p /var/lib/super_box && sudo chmod 777 /var/lib/super_box")
    stdout_dir.channel.recv_exit_status()

    # 4. Transfer the Rust files directly onto the server using SFTP
    print("[*] Transferring Super Box Rust core files to remote server...")
    sftp = ssh.open_sftp()
    try:
        sftp.mkdir("/var/lib/super_box/src")
    except:
        pass
    try:
        sftp.mkdir("/var/lib/super_box/src/hidekey")
    except:
        pass
    try:
        sftp.mkdir("/var/lib/super_box/src/hideui")
    except:
        pass
    try:
        sftp.mkdir("/var/lib/super_box/frontend")
    except:
        pass

    # Transfer files
    local_files = [
        ("Cargo.toml", "/var/lib/super_box/Cargo.toml"),
        ("src/lib.rs", "/var/lib/super_box/src/lib.rs"),
        ("src/main.rs", "/var/lib/super_box/src/main.rs"),
        ("src/config.rs", "/var/lib/super_box/src/config.rs"),
        ("src/inbound.rs", "/var/lib/super_box/src/inbound.rs"),
        ("src/outbound.rs", "/var/lib/super_box/src/outbound.rs"),
        ("src/stats.rs", "/var/lib/super_box/src/stats.rs"),
        ("src/tls13.rs", "/var/lib/super_box/src/tls13.rs"),
        ("src/tun_device.rs", "/var/lib/super_box/src/tun_device.rs"),
        ("src/hidekey/mod.rs", "/var/lib/super_box/src/hidekey/mod.rs"),
        ("src/hidekey/crypto.rs", "/var/lib/super_box/src/hidekey/crypto.rs"),
        ("src/hidekey/handshake.rs", "/var/lib/super_box/src/hidekey/handshake.rs"),
        ("src/hidekey/stego.rs", "/var/lib/super_box/src/hidekey/stego.rs"),
        ("src/hidekey/framing.rs", "/var/lib/super_box/src/hidekey/framing.rs"),

        ("src/hideui/mod.rs", "/var/lib/super_box/src/hideui/mod.rs"),
        ("src/hideui/db.rs", "/var/lib/super_box/src/hideui/db.rs"),
        ("src/hideui/handlers.rs", "/var/lib/super_box/src/hideui/handlers.rs"),
        ("frontend/index.html", "/var/lib/super_box/frontend/index.html"),
        ("menu.sh", "/var/lib/super_box/menu.sh"),
    ]

    for local, remote in local_files:
        try:
            sftp.put(local, remote)
        except Exception as e:
            print(f"[!] Warning: could not transfer file {local} to {remote}: {e}")

    sftp.close()

    # 4b. Make management menu executable and register system-wide hide-ui command shortcut
    ssh.exec_command("chmod +x /var/lib/super_box/menu.sh")
    ssh.exec_command("sudo ln -sf /var/lib/super_box/menu.sh /usr/local/bin/hide-ui && sudo chmod +x /usr/local/bin/hide-ui")

    # 5. Build release binary on the remote server
    print("[*] Building Super Box core on remote server (this may take 1-2 minutes)...")
    build_cmd = f"bash -c '{path_cmd} && cd /var/lib/super_box && $HOME/.cargo/bin/cargo build --release'"
    stdin, stdout, stderr = ssh.exec_command(build_cmd)
    
    # Block and wait for build to complete
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        err = stderr.read().decode().strip()
        print(f"[-] Build failed on server: {err}")
        return
    
    print("[SUCCESS] Release build completed successfully on remote server!")

    # 6. Spawn the panel in the background
    print("[*] Launching Hide-UI Web Panel on remote port 8082 in background...")
    ssh.exec_command("sudo killall -9 super_box || true")
    import time
    time.sleep(1.5) # Wait for database file locks to be fully released by OS
    launch_cmd = "nohup bash -c 'cd /var/lib/super_box && ./target/release/super_box server' > /var/log/super_box.log 2>&1 &"
    ssh.exec_command(launch_cmd)

    print("[SUCCESS] Hide-UI has been deployed and launched!")
    print(f"[*] Access the Panel at: http://{ip}:8082")
    print("[*] Default Login Credentials:")
    print("    Username: admin")
    print("    Password: hidekey2026")

    ssh.close()

if __name__ == "__main__":
    deploy()
