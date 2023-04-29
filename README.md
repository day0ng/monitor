# monitor

## Help

```shell
shell> python systemInfo.py
usage: systemInfo.py [-h] [--all] [--battery] [--cpu] [--disk] [--error] [--hostname HOSTNAME] [--inode]
                     [--io] [--json] [--load] [--mail_from MAIL_FROM] [--mail_password MAIL_PASSWORD]
                     [--mail_to MAIL_TO] [--memory] [--network] [--os] [--service SERVICE]
                     [--smtp_host SMTP_HOST] [--smtp_port SMTP_PORT] [--uptime] [--verbose] [--version]

  This is realtime system monitoring program, and it could be run at Windows,
  Linux and MacOS.

options:
  -h, --help            show this help message and exit
  --all, -a             all system information
  --battery             battery information
  --cpu                 CPU information
  --disk                disk information
  --error               errors log
  --hostname HOSTNAME   set hostname
  --inode               inodes information (unix only)
  --io                  IO read and write information
  --json                JSON output
  --load                system load information
  --mail_from MAIL_FROM
                        username for SMTP authentication
  --mail_password MAIL_PASSWORD
                        password for SMTP authentication
  --mail_to MAIL_TO     email addresses to recieve the infomation
  --memory              memory information
  --network             network information
  --os                  OS information
  --service SERVICE     servcie information
  --smtp_host SMTP_HOST
                        hostname of SMTP server
  --smtp_port SMTP_PORT
                        port number of SMTP server
  --uptime              system uptime
  --verbose, -v         verbose output
  --version, -V         version number of this program
```


## Example

```bash
bash> python systemInfo.py --cpu --battery
hostname = NONAME
datetime = 2023-04-29 18:29:22
battery = {'charge': '100%', 'time_left': 'power_plugged'}
cpu = {'total_usage': 4.1}
```

```bash
bash> python systemInfo.py --cpu --battery --json
{"hostname": "NONAME", "datetime": "2023-04-29 18:29:31", "battery": {"charge": "100%", "time_left": "power_plugged"}, "cpu": {"total_usage": 5.8}}
```

```powershell
powershell> python c:\Tools\monitor\systemInfo.py --cpu --mem --disk --battery --uptime --version --service "bits;wuauserv" --smtp_host smtp.test.net --smtp_port 465 --mail_from monitor@test.net --mail_password xxxxxxxx --mail_to admin@test.net --hostname %computername%
```
