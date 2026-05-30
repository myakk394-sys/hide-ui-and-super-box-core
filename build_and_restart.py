import paramiko
import time
import sys

ip = "YOUR_VPS_IP"
username = "root"
password = "YOUR_SSH_PASSWORD"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(ip, username=username, password=password, timeout=15)
print("[OK] Connected to VPS")

# Compile
print("[*] Building release binary on VPS (may take 2-5 min)...")
build_cmd = "source $HOME/.cargo/env && cd /var/lib/super_box && cargo build --release 2>&1"
stdin, stdout, stderr = ssh.exec_command(build_cmd, timeout=600)
out = stdout.read().decode("utf-8", errors="replace")
code = stdout.channel.recv_exit_status()
print(out[-3000:] if len(out) > 3000 else out)
if code != 0:
    print(f"BUILD FAILED with code {code}")
    ssh.close()
    sys.exit(1)
print("[OK] Build successful")

# Stop, update, restart
print("[*] Stopping superbox service...")
stdin, stdout, stderr = ssh.exec_command("systemctl stop superbox")
stdout.channel.recv_exit_status()
time.sleep(1)
stdin, stdout, stderr = ssh.exec_command("pkill -f /var/lib/super_box/python3 2>/dev/null || true")
stdout.channel.recv_exit_status()
time.sleep(1)

print("[*] Copying new binary to python3...")
stdin, stdout, stderr = ssh.exec_command("cp /var/lib/super_box/target/release/super_box /var/lib/super_box/python3")
stdout.channel.recv_exit_status()

print("[*] Starting superbox service...")
stdin, stdout, stderr = ssh.exec_command("systemctl start superbox")
stdout.channel.recv_exit_status()
time.sleep(3)

# Show status
print("[*] Service status:")
stdin, stdout, stderr = ssh.exec_command("systemctl is-active superbox")
print("Active:", stdout.read().decode().strip())

stdin, stdout, stderr = ssh.exec_command("ps aux | grep python3 | grep -v grep")
print("\n=== Active processes on VPS ===")
print(stdout.read().decode("utf-8", errors="replace"))

stdin, stdout, stderr = ssh.exec_command("journalctl -u superbox -n 25 --no-pager")
print(stdout.read().decode("utf-8", errors="replace"))

ssh.close()
print("[DONE] Deployment complete!")
