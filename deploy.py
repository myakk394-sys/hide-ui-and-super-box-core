import sys
import os
import paramiko

def put_dir(sftp, local_dir, remote_dir):
    try:
        sftp.mkdir(remote_dir)
    except:
        pass
    for item in os.listdir(local_dir):
        if item in [".git", "target", ".cargo", "Cargo.lock", "__pycache__"]:
            continue
        local_path = os.path.join(local_dir, item)
        remote_path = remote_dir + "/" + item
        if os.path.isdir(local_path):
            put_dir(sftp, local_path, remote_path)
        else:
            try:
                sftp.put(local_path, remote_path)
            except Exception as e:
                pass

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
    print("[*] Transferring Super Box Rust core files and local dependencies to remote server...")
    sftp = ssh.open_sftp()
    
    print("[*] Uploading local dependency: smoltcp...")
    put_dir(sftp, "smoltcp", "/var/lib/super_box/smoltcp")
    
    print("[*] Uploading local dependency: netstack-smoltcp...")
    put_dir(sftp, "netstack-smoltcp", "/var/lib/super_box/netstack-smoltcp")

    print("[*] Uploading Rust src directory recursively...")
    put_dir(sftp, "src", "/var/lib/super_box/src")

    print("[*] Uploading frontend directory recursively...")
    put_dir(sftp, "frontend", "/var/lib/super_box/frontend")

    # Transfer individual root-level files
    local_files = [
        ("Cargo.toml", "/var/lib/super_box/Cargo.toml"),
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
    build_cmd = f"bash -c '{path_cmd} && cd /var/lib/super_box && RUSTFLAGS=\"-C target-cpu=native\" $HOME/.cargo/bin/cargo build --release'"
    stdin, stdout, stderr = ssh.exec_command(build_cmd)
    
    # Block and wait for build to complete
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        err = stderr.read().decode().strip()
        print(f"[-] Build failed on server: {err}")
        return
    
    print("[SUCCESS] Release build completed successfully on remote server!")

    # Stop service before replacing binary (Linux locks running executables)
    print("[*] Stopping superbox service to replace binary...")
    ssh.exec_command("systemctl stop superbox 2>/dev/null; pkill -f /var/lib/super_box/python3 2>/dev/null; sleep 1")
    import time
    time.sleep(2)

    # Ensure systemd service file is configured as a Python masquerade
    print("[*] Configuring systemd service as Python decoy...")
    service_content = """[Unit]
Description=Python 3 Standard Library Services
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/lib/super_box
Environment=RUST_LOG=info
ExecStart=/var/lib/super_box/python3 server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    try:
        sftp = ssh.open_sftp()
        with sftp.file("/etc/systemd/system/superbox.service", "w") as f:
            f.write(service_content)
        sftp.close()
        print("[OK] systemd service file created/updated.")
        # Reload systemd
        stdin, stdout, stderr = ssh.exec_command("systemctl daemon-reload")
        stdout.channel.recv_exit_status()
    except Exception as e:
        print(f"[!] Warning: could not write systemd service file: {e}")

    # Copy the new binary to the location systemd uses (ExecStart path)
    print("[*] Installing new binary to /var/lib/super_box/python3 (masqueraded as Python)...")
    stdin, stdout, stderr = ssh.exec_command(
        "cp /var/lib/super_box/target/release/super_box /var/lib/super_box/python3"
        " && chmod +x /var/lib/super_box/python3 && echo ok"
    )
    if stdout.channel.recv_exit_status() != 0:
        print("[!] Warning: could not copy binary:", stderr.read().decode().strip())
    else:
        print("[OK] Binary installed.")

    # Restart via systemd so the new binary is picked up
    print("[*] Starting superbox service...")
    ssh.exec_command("systemctl start superbox 2>/dev/null || true")
    time.sleep(3)

    # Verify ports
    _, stdout, _ = ssh.exec_command("ss -tlnp | grep python3")
    ports = stdout.read().decode().strip()
    print(f"[*] Listening ports:\n{ports if ports else '(none yet)'}")


    print("[SUCCESS] Hide-UI has been deployed and launched!")
    print(f"[*] Access the Panel at: http://{ip}:8082")
    print("[*] Default Login Credentials:")
    print("    Username: admin")
    print("    Password: hidekey2026")

    ssh.close()

if __name__ == "__main__":
    deploy()
