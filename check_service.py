import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('YOUR_VPS_IP', username='root', password='YOUR_SSH_PASSWORD', timeout=15)

_, stdout, _ = ssh.exec_command('cat /etc/systemd/system/superbox.service 2>/dev/null || systemctl cat superbox 2>/dev/null')
print(stdout.read().decode())

_, stdout, _ = ssh.exec_command('ls -la /var/lib/super_box/target/release/super_box 2>/dev/null && stat -c "%y" /var/lib/super_box/target/release/super_box')
print('Binary:', stdout.read().decode().strip())

ssh.close()
