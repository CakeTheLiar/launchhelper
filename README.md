# Contents

### frida/
  
  Contains handlers for calling frida (https://frida.re/) directly. You will not need these unless you want to debug things yourself.

### launchhelper.sh
  
  A version of the old launchhelper script that displays the elapsed time

### launchhelper2.py
  
  `python3 launchhelper2.py`

  Requires python>=3.8, psutil (`pip install psutil`)

  Requires injector.py

  Does not require `sudo`

  This version of Launchhelper 2 will attempt install Python inside of your WINEPREFIX and then automate running injector.py inside of it.

  Installing Python inside of Wine is the most common point of failure. If you're having trouble with this, try `sulaunchhelper.py` instead.


### injector.py

  This script will install frida inside of your WINEPREFIX if it does not exist already, and then inject the patch necessary for the login into `RiotClientServices.exe->WS2_32.dll->select`

### sulaunchhelper2.py

  `sudo python3 sulaunchhelper2.py`

  Requires python>=3.8, psutil, frida (`pip install psutil frida`)

  Requires `sudo`

  This version of Launchhelper 2 will attempt to inject the necessary patch from outside of Wine. It therefore requires to be run under `sudo`, but does not need to install Python inside your WINEPREFIX, which should make it work more consistently across platforms.

# Troubleshooting

## Installing Python inside Wine fails

This can happen due to multiple unknown reasons.
Setting your reported Windows version to Windows 10 may sometimes fix this.

One other possible reason may be that you don't own all the files inside the WINEPREFIX.
You can fix this by running 
```sh
export WINEPREFIX=/path/to/wineprefix
chown -R $(whoami):$(whoami) $WINEPREFIX
```

You can also attempt to install Python manually. This should at least give you a more detailed error message
```sh
export WINEPREFIX=/path/to/wineprefix
export WINEARCH=win32 # or win64, depending on what you use

wget "https://www.python.org/ftp/python/3.8.9/python-3.8.9.exe"
# or if you use a 64bit prefix
wget "https://www.python.org/ftp/python/3.8.9/python-3.8.9-amd64.exe"

/path/to/wine-lol python-3.8.9.exe
```

If the problem persists, try using `sulaunchhelper2.py` instead

## AttributeError: module 'frida' has no attribute 'attach'

This may happen for both versions of the script and it's a bug where `frida` does not get installed properly. Unfortunately that appears to be a random bug with the `frida` package and usually is fixable by simply reinstalling it.

### For launchhelper2.py / injector.py:
```sh
export WINEPREFIX=/path/to/wineprefix

/path/to/wine-lol pip uninstall frida
/path/to/wine-lol pip install frida
```

### For sulaunchhelper.py:
```sh
pip uninstall frida
pip install frida
```
