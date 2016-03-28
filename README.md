ZFS auto snapshot.
Based on FreeNAS autosnap.py script.

Usage:
autosnap.py -f config.cfg

Add task to crontab:
@hourly autosnap.py -f config.cfg