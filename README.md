# spooky_process_py
Find a directory in proc that doesn't appear in ps -efL. May indicate a root kit.

Living off the land, no external dependencies, but this does require Python3.

Tested and working on Python 3.5+

# Usage
Test and working as root, might work as a regular user but that is untested.

prompt# python3 spookyprocess.py  
We have found the follow suspicious PIDs:  
9577  
8138   
