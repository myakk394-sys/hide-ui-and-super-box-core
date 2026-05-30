import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('YOUR_VPS_IP', username='root', password='YOUR_SSH_PASSWORD', timeout=15)

cmds = [
    ('Listening ports', 'ss -tlnp'),
    ('Service status',  'systemctl is-active superbox 2>/dev/null || echo no-systemd'),
    ('Processes',       'ps aux | grep super_box | grep -v grep'),
    ('Last log lines',  'tail -20 /var/log/super_box.log 2>/dev/null || journalctl -u superbox -n 20 --no-pager 2>/dev/null'),
]

for label, cmd in cmds:
    _, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    print(f'\n=== {label} ===')
    if out: print(out)
    if err: print('ERR:', err)

ssh.close()
