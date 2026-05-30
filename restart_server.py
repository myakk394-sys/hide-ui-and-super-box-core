import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('YOUR_VPS_IP', username='root', password='YOUR_SSH_PASSWORD', timeout=15)

cmds = [
    ('Stop old process',    'killall -9 super_box 2>/dev/null; sleep 1; echo done'),
    ('Restart service',     'systemctl restart superbox 2>/dev/null && echo restarted || echo no-service'),
    ('Wait for startup',    'sleep 3 && echo waited'),
    ('Check ports',         'ss -tlnp | grep super_box'),
]

for label, cmd in cmds:
    _, stdout, stderr = ssh.exec_command(cmd)
    stdout.channel.recv_exit_status()
    out = stdout.read().decode().strip()
    print(f'{label}: {out}')

ssh.close()
print('Done.')
