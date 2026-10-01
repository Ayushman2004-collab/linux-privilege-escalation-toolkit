# Practical Commands and Screenshot Checklist

## Installation
```bash
python3 --version
cd linux_privesc_toolkit
```

## Run fast scan
```bash
python3 main.py --fast
```

## Run full scan
```bash
python3 main.py
```

## Individual Linux commands for demonstration
```bash
id
uname -a
cat /etc/os-release
find / -type f -perm -4000 2>/dev/null
find / -type f -perm -2000 2>/dev/null
sudo -l
crontab -l
systemctl list-units --type=service --state=running --no-pager
getcap -r / 2>/dev/null
```

## Screenshots to capture
1. `python3 --version`
2. `id` and `uname -a`
3. Toolkit startup
4. SUID/SGID findings
5. Permission findings
6. Sudo findings (on a lab account)
7. Cron findings
8. Systemd findings
9. Final terminal summary
10. HTML report opened in a browser

## Safe lab evidence
A simple harmless permission test:
```bash
touch /tmp/privesc_lab.txt
chmod 666 /tmp/privesc_lab.txt
python3 main.py --fast
rm -f /tmp/privesc_lab.txt
```

Do not turn the lab condition into an exploit. The goal is to demonstrate detection and reporting.
