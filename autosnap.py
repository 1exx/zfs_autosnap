#!/usr/bin/env python

import logging
import os
import re
import sys

# pipesubr.py
from shlex import split as shlex_split
from subprocess import Popen, PIPE

from datetime import datetime, time, timedelta

# setup ability to log to syslog
logging.NOTICE = 60
logging.addLevelName(logging.NOTICE, "NOTICE")
log = logging.getLogger('autosnap')

# Set to True if verbose log desired
debug = False

# pipesubr.py
def fastclose():
    #FIXME: Take into account keep_fd and determine which fds from /dev/fd
    # or fstat. See #10206
    for fd in range(3, 1024):
        try:
            os.close(fd)
        except OSError:
            pass

# pipesubr.py
def pipeopen(command, important=True, logger=log, allowfork=False, quiet=False):
    if not quiet:
        logger.log(logging.NOTICE if important else logging.DEBUG,
            "Popen()ing: " + command)
    args = shlex_split(str(command))

    preexec_fn = fastclose

    return Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE,
        close_fds=False, preexec_fn=preexec_fn)

def isTimeBetween(time_to_test, begin_time, end_time):
    if begin_time <= end_time:
        # e.g. from 9:00 to 18:00.  This also covers e.g. 18:00 to 18:00
        # which means the event happens on exactly 18:00.
        return ((time_to_test >= begin_time) and (time_to_test <= end_time))
    else:
        # e.g. from 18:00 to 9:00
        return ((time_to_test >= begin_time) or (time_to_test <= end_time))

def snapinfodict2datetime(snapinfo):
    year = int(snapinfo['year'])
    month = int(snapinfo['month'])
    day = int(snapinfo['day'])
    hour = int(snapinfo['hour'])
    minute = int(snapinfo['minute'])
    return datetime(year, month, day, hour, minute)

def snap_expired(snapinfo, snaptime):
    snapinfo_expirationtime = snapinfodict2datetime(snapinfo)
    snap_ttl_value = int(snapinfo['retcount'])
    snap_ttl_unit = snapinfo['retunit']

    if snap_ttl_unit == 'h':
        snapinfo_expirationtime = snapinfo_expirationtime + timedelta(hours = snap_ttl_value)
    elif snap_ttl_unit == 'd':
        snapinfo_expirationtime = snapinfo_expirationtime + timedelta(days = snap_ttl_value)
    elif snap_ttl_unit == 'w':
        snapinfo_expirationtime = snapinfo_expirationtime + timedelta(days = 7*snap_ttl_value)
    elif snap_ttl_unit == 'm':
        snapinfo_expirationtime = snapinfo_expirationtime + timedelta(days = int(30.436875*snap_ttl_value))
    elif snap_ttl_unit == 'y':
        snapinfo_expirationtime = snapinfo_expirationtime + timedelta(days = int(365.2425*snap_ttl_value))

    return snapinfo_expirationtime <= snaptime

def isMatchingTime(task, snaptime):
    curtime = time(snaptime.hour, snaptime.minute)
    repeat_type = task.task_repeat_unit
    '''
    task_repeat_unit = models.CharField(
        default='weekly',
        max_length=120,
        choices=choices.RepeatUnit_Choices,
        verbose_name=_("Occurrence"),
        help_text=_("How the task is repeated"),
    )
    RepeatUnit_Choices = (
        ('daily', _('Everyday')),
        ('weekly', _('Every selected weekday')),
        # ('monthly', _('Every these days of month')),
        # ('yearly', _('Every these days of specified months')),
    )
    '''

    if not isTimeBetween(curtime, task.task_begin, task.task_end):
        return False
    '''
    task_begin = models.TimeField(
        default=time(hour=9),
        verbose_name=_("Begin"),
        help_text=_("Do not snapshot before"),
    )
    task_end = models.TimeField(
        default=time(hour=18),
        verbose_name=_("End"),
        help_text=_("Do not snapshot after"),
    )
    '''
    if repeat_type == 'daily':
        return True

    '''
    task_byweekday = models.CharField(
        max_length=120,
        default="1,2,3,4,5",
        verbose_name=_("Weekday"),
        blank=True,
    )
    '''
    if repeat_type == 'weekly':
        cur_weekday = snaptime.weekday() + 1
        if ('%d' % cur_weekday) in task.task_byweekday.split(','):
            return True

    return False

# Detect if another instance is running
def exit_if_running(pid):
    log.debug("Checking if process %d is still alive", pid)
    try:
        os.kill(pid, 0)
        # If we reached here, there is another process in progress
        log.debug("Process %d still working, quitting", pid)
        sys.exit(0)
    except OSError:
        log.debug("Process %d gone", pid)

mypid = os.getpid()

AUTOSNAP_PID = -1
try:
    with open('/var/run/autosnap.pid') as pidfile:
        AUTOSNAP_PID = int(pidfile.read())
except:
    pass

if AUTOSNAP_PID != -1:
    exit_if_running(AUTOSNAP_PID)

with open('/var/run/autosnap.pid', 'w') as pidfile:
    pidfile.write('%d' % mypid)

#MNTLOCK.unlock()

now = datetime.now().replace(microsecond=0)
if now.second < 30 or now.minute == 59:
    snaptime = now.replace(second=0)
else:
    snaptime = now.replace(minute=now.minute + 1, second=0)

mp_to_task_map = {}

# Grab all matching tasks into a tree.
# Since the snapshot we make have the name 'foo@auto-%Y%m%d.%H%M-{expire time}'
# format, we just keep one task.
TaskObjects = Task.objects.filter(task_enabled=True)
taskpath = {'recursive': [], 'nonrecursive': []}
for task in TaskObjects:
    if isMatchingTime(task, snaptime):
        '''
        task_filesystem = models.CharField(
            max_length=150,
            verbose_name=_("Volume/Dataset"),
        )

        task_recursive = models.BooleanField(
            default=False,
            verbose_name=_("Recursive"),
        )

        task_ret_count = models.PositiveIntegerField(
            default=2,
            verbose_name=_("Snapshot lifetime value"),
        )

        task_ret_unit = models.CharField(
            default='week',
            max_length=120,
            choices=choices.RetentionUnit_Choices,
            verbose_name=_("Snapshot lifetime unit"),
        )
        '''
        if task.task_recursive:
            taskpath['recursive'].append(task.task_filesystem)
        else:
            taskpath['nonrecursive'].append(task.task_filesystem)
        fs = task.task_filesystem
        expire_time = ('%s%s' % (task.task_ret_count, task.task_ret_unit[0])).__str__()
        tasklist = []
        if mp_to_task_map.has_key((fs, expire_time)):
            tasklist = mp_to_task_map[(fs, expire_time)]
            tasklist.append(task)
        else:
            tasklist = [task]
        mp_to_task_map[(fs, expire_time)] = tasklist

re_path = re.compile("^((" + '|'.join(taskpath['nonrecursive']) +
                     ")@|(" + '|'.join(taskpath['recursive']) + ")[@/])")
# Only proceed further if we are  going to generate any snapshots for this run
if len(mp_to_task_map) > 0:

    # Grab all existing snapshot and filter out the expiring ones
    snapshots = {}
    snapshots_pending_delete = set()
    zfsproc = pipeopen("/sbin/zfs list -t snapshot -H", debug, logger=log)
    lines = zfsproc.communicate()[0].split('\n')
    reg_autosnap = re.compile('^auto-(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2}).(?P<hour>\d{2})(?P<minute>\d{2})-(?P<retcount>\d+)(?P<retunit>[hdwmy])$')
    for line in lines:
        if line != '':
            snapshot_name = line.split('\t')[0]
            fs, snapname = snapshot_name.split('@')
            snapname_match = reg_autosnap.match(snapname)
            if snapname_match != None:
                snap_infodict = snapname_match.groupdict()
                snap_ret_policy = '%s%s' % (snap_infodict['retcount'], snap_infodict['retunit'])
                if snap_expired(snap_infodict, snaptime):
                    # Only delete the snapshot if there's a snapshot task enabled that created it.
                    if re_path:
                        if re_path.match(snapshot_name):
                            snapshots_pending_delete.add(snapshot_name)
                else:
                    if mp_to_task_map.has_key((fs, snap_ret_policy)):
                        if snapshots.has_key((fs, snap_ret_policy)):
                            last_snapinfo = snapshots[(fs, snap_ret_policy)]
                            if snapinfodict2datetime(last_snapinfo) < snapinfodict2datetime(snap_infodict):
                                snapshots[(fs, snap_ret_policy)] = snap_infodict
                        else:
                            snapshots[(fs, snap_ret_policy)] = snap_infodict

    list_mp = mp_to_task_map.keys()

    for mpkey in list_mp:
        tasklist = mp_to_task_map[mpkey]
        if snapshots.has_key(mpkey):
            snapshot_time = snapinfodict2datetime(snapshots[mpkey])
            for taskindex in range(len(tasklist) -1, -1, -1):
                task = tasklist[taskindex]
                '''
                TASK_INTERVAL = (
                    (5, _("%(minutes)s minutes") % {'minutes': '5'}),
                    (10, _("%(minutes)s minutes") % {'minutes': '10'}),
                    (15, _("%(minutes)s minutes") % {'minutes': '15'}),
                    (30, _("%(minutes)s minutes") % {'minutes': '30'}),
                    (60, _("%(hour)s hour") % {'hour': '1'}),
                    (120, _("%(hours)s hours") % {'hours': '2'}),
                    (180, _("%(hours)s hours") % {'hours': '3'}),
                    (240, _("%(hours)s hours") % {'hours': '4'}),
                    (360, _("%(hours)s hours") % {'hours': '6'}),
                    (720, _("%(hours)s hours") % {'hours': '12'}),
                    (1440, _("%(day)s day") % {'day': '1'}),
                    (10080, _("%(week)s week") % {'week': '1'}),
                    (20160, _("%(weeks)s weeks") % {'weeks': '2'}),
                    (40320, _("%(weeks)s weeks") % {'weeks': '4'}),
                )
                task_interval = models.PositiveIntegerField(
                    default=60,
                    choices=choices.TASK_INTERVAL,
                    max_length=120,
                    verbose_name=_("Interval"),
                    help_text=_(
                        "How much time has been passed between two snapshot attempts."),
                )
                '''
                if snapshot_time + timedelta(minutes = task.task_interval) > snaptime:
                    del tasklist[taskindex]
            if len(tasklist) == 0:
                del mp_to_task_map[mpkey]

    snaptime_str = snaptime.strftime('%Y%m%d.%H%M')

    for mpkey, tasklist in mp_to_task_map.items():
        fs, expire = mpkey
        recursive = False
        for task in tasklist:
            if task.task_recursive == True:
                recursive = True
        if recursive == True:
            rflag = ' -r'
        else:
            rflag = ''

        snapname = '%s@auto-%s-%s' % (fs, snaptime_str, expire)

        # Do a snapshot
        snapcmd = '/sbin/zfs snapshot%s "%s"' % (rflag, snapname)
        proc = pipeopen(snapcmd, logger=log)
        err = proc.communicate()[1]
        if proc.returncode != 0:
            log.error("Failed to create snapshot '%s': %s", snapname, err)

    #MNTLOCK.lock()
    for snapshot in snapshots_pending_delete:
        snapcmd = '/sbin/zfs destroy -r -d "%s"' % (snapshot) #snapshots with clones will have destruction deferred
        proc = pipeopen(snapcmd, logger=log)
        err = proc.communicate()[1]
        if proc.returncode != 0:
            log.error("Failed to destroy snapshot '%s': %s", snapshot, err)
    #MNTLOCK.unlock()


os.unlink('/var/run/autosnap.pid')
