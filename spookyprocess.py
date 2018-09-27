"""spookyprocess

Look for possible rootkit activity by finding impossible directories in /proc.

Prints suspicious processes to the screen

git: https://github.com/dagonis/spooky_process_py
author: Kevin Tyers
"""
#!/usr/bin/python3
import os
import subprocess
import sys

if sys.version_info.major < 3:
    print("You must use Python3 for this script.\nex. python3 spookyprocess.py")
    sys.exit(-127)

class Process:
    """Light weight Process class, written this way to be extensible later.
    """

    def __init__(self, uid, pid, ppid, lwp, c, nlwp, stime, tty, time, cmd):
        """Constructor, probably a pain to invoke directly. Use Process.create_process()
        with a line of output from ps -efL instead.

        Arguments:
            uid {bytes} -- [description]
            pid {int} -- [description]
            ppid {int} -- [description]
            lwp {int} -- [description]
            c {int} -- [description]
            nlwp {int} -- [description]
            stime {bytes} -- [description]
            tty {bytes} -- [description]
            time {bytes} -- [description]
            cmd {bytes} -- [description]
        """
        self.uid = uid.decode()
        self.pid = int(pid)
        self.ppid = int(ppid)
        self.lwp = int(lwp)
        self.c = int(c)
        self.nlwp = int(nlwp)
        self.stime = stime.decode()
        self.tty = tty.decode()
        self.time = time.decode()
        self.cmd = cmd.decode()

    @classmethod
    def create_process(cls, raw_proc):
        """Take a line from ps -efL and turn it into a Process object!

        Arguments:
            raw_proc {str} -- A line from ps -efL
            ex.
            root      8135  7125  8135  0    1 19:48 pts/1    00:00:00 sh

        Returns:
            Process -- Process Object
        """
        _clean_proc = []
        for col in raw_proc.split(b" "):
            if len(col) > 0:
                _clean_proc.append(col)
        if len(_clean_proc) > 10:
            single_command = b" ".join(_clean_proc[10:])
            _clean_proc = _clean_proc[:9]
            _clean_proc.append(single_command)
        return cls(*_clean_proc)  # Forgive me for this, but it works.

    def __str__(self):
        # We can make this cool later
        return str(self.__dict__)


def get_all_processes():
    """Get all processes via ps -efL then
    chop them up and load into objects for ease of handling.

    Returns:
        list -- A list of Process objects
    """
    cleaned_process = []
    lw_processes = subprocess.check_output('ps -efL', shell=True)
    for lw_process in lw_processes.splitlines()[1:]:
        try:
            cleaned_process.append(Process.create_process(lw_process))
        except Exception as e:
            print(e)
    return cleaned_process

def get_all_process_ids(processes):
    """Given an iterable of processes, get pid, ppid, and lwp
    and put them in a set (we don't care about duplicates)

    Arguments:
        processes {some_iter} -- An interable(probably a list) of processes

    Returns:
        set -- all see process IDs
    """
    all_processes = set()
    for process in processes:
        all_processes.add(process.pid)
        all_processes.add(process.ppid)
        all_processes.add(process.lwp)
    return all_processes

if __name__ == '__main__':
    if os.getuid() > 0:
        print("You should think about running this as root, but it may still work.")
    # Figure out how many pids we need to check.
    with open('/proc/sys/kernel/pid_max', 'r') as max_pid_file:
        max_pid = int(max_pid_file.read().strip())
    # Let's grab all the processes from the system
    known_processes = get_all_processes()
    # Let's get all the process IDs so we don't check for valid /proc/ directories
    all_process_ids = get_all_process_ids(known_processes)
    pids_to_check = [_ for _ in range(max_pid) if _ not in all_process_ids]
    # Let's start checking! We are going to do two checks
    # We will check if the dir exists and then we will try to cd into it
    # If we see it and/or can CD into it, we may have a hidden_pid
    possible_hidden_pids = set()
    for pid_to_check in pids_to_check:
        if os.path.exists('/proc/{}'.format(pid_to_check)):
            possible_hidden_pids.add(pid_to_check)
        try:
            os.chdir('/proc/{}'.format(pid_to_check))
            possible_hidden_pids.add(pid_to_check)
        except FileNotFoundError:
            # expected!
            pass
        except Exception as e:
            print("pid: {} Unhandled exception {}".format(pid_to_check, e))
    if len(possible_hidden_pids) > 0:
        print("We have found the follow suspicious PIDs:\n{}".format("\n".join([str(pid) for pid in possible_hidden_pids])))
    else:
        print("We did not find any suspicious PIDs")
