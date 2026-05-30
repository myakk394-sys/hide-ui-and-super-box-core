import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('YOUR_VPS_IP', username='root', password='YOUR_SSH_PASSWORD', timeout=15)

cmds = [
    'stat /var/lib/super_box/super_box',
    'ls -la /var/lib/super_box/super_box',
    'md5sum /var/lib/super_box/super_box /var/lib/super_box/target/release/super_box',
    'ss -tlnp | grep super_box',
]
for cmd in cmds:
    _, stdout, _ = ssh.exec_command(cmd)
    out = stdout.read().decode().strip()
    print(f'$ {cmd}\n{out}\n')

ssh.close()
