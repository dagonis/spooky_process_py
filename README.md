# spooky_process_py
Find a directory in proc that doesn't appear in ps -efL. May indicate a root kit.

Living off the land, no external dependencies, but this does require Python3.

Tested and working on Python 3.5+

# Installation

Run `git clone https://github.com/dagonis/spooky_process_py.git`

Then `cd spooky_process_py/`

Finally run `sudo python3 spookyprocess.py`

# Usage
Test and working as root, might work as a regular user but that is untested.

prompt# python3 spookyprocess.py  
We have found the follow suspicious PIDs:  
9577  
8138   

# Rootkits tested

Tested and confirmed working against the following Rootkits:

https://github.com/nurupo/rootkit  
https://github.com/f0rb1dd3n/Reptile  
https://github.com/mncoppola/suterusu  