# autoOSINT
A silly script to save a few seconds during triage.<br> 
- Opens a bunch of tabs of different OSINT tools in the system's default browser based on a IOC input.<br>
- Supports IP, Domain, URL, and SHA256 Hash input.<br> 

<br>

## Windows
1) Download [autoOSINT.py](https://github.com/isaacward1/autoOSINT/blob/main/autoOSINT.py)
2) Make sure .py files are set to open via python interpreter (Settings > File association is set to
3) `cd` into directory with autoOSINT.py
4) `.\autoOSINT.py <ioc>`


<br>

## *nix
1) Download [autoOSINT.py](https://github.com/isaacward1/autoOSINT/blob/main/autoOSINT.py)
2) `cd` into directory with autoOSINT.py
3) `chmod +x autoOSINT.py`
4) Ensure '/usr/local/bin' is in $PATH environment variable: `echo $PATH | tr ':' '\n'`
5) `sudo mv autoOSINT.py /usr/local/bin/autoOSINT.py`
6) `autoOSINT <ioc>`

<br>

## Issues
- Depending on your browser configurations, you may need to open a new window first
- 
