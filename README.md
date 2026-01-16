# autoOSINT
A silly CLI tool to save a few seconds during triage.<br>
- Opens a bunch of tabs of different OSINT tools/feeds in the system's default browser based on a IOC input.<br>
- Supports IP(v4), Domain, URL, and SHA-256 Hash input.<br>

<br>

## Windows
1) Download [autoOSINT.py](https://github.com/isaacward1/autoOSINT/blob/main/autoOSINT.py)<br>
2) Recommended: set '.py' files to open via python interpreter (not an IDE): <br>
   [Settings > Apps > Default apps > Choose defaults by file type > Default for '.py' files: Python]
3) `cd` into directory with autoOSINT.py
4) `autoOSINT.py <IOC>` or `autoOSINT.py -h` for usage


<br>

## *nix
1) Download [autoOSINT.py](https://github.com/isaacward1/autoOSINT/blob/main/autoOSINT.py)
2) `cd` into directory with autoOSINT.py
3) `chmod +x autoOSINT.py`
4) Ensure '/usr/local/bin' is in $PATH environment variable: `echo $PATH | tr ':' '\n'`
5) `sudo mv autoOSINT.py /usr/local/bin/autoOSINT.py`
6) `autoOSINT.py <IOC>` or `autoOSINT.py -h` for usage

<br>

## Note
- Some sources require an account for full functionality. These are marked with comments.
- Default sources can be added/removed by editing 'default' arrays.
- `webbrowser` will attempt to open a fresh browser window first and then new tabs for subsequent links. However, depending on browser settings/version, a new window may need to be manually opened and focused before running the tool to prevent cluttering of an active window.

<br>
