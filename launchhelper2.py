#!/usr/bin/env python3

import psutil
import socket
import ssl
import time
import subprocess
import sys
import os
import urllib.request
import signal

"""
    requires psutil (pip install psutil)
    requires injector.py

    Launchhelper2 will try to lauch the League of Legends client by instrumenting frida (https://frida.re/)
    This version does not require sudo.
    It will launch frida by starting a subprocess inside your WINEPREFIX
"""

injector_use_binary = False # setting this to true will download the binary if it doesn't exist already

sleep_time = 1
timeout = 0 # 0 to disable

hide_backtrace = True

python_executable = 'py' # use py utility instead of python.exe Try to edit this if you're having problems

injector_script = 'injector.py'
injector_binary = 'lhinjector.exe'
injector_download_url = 'https://github.com/CakeTheLiar/launchhelper/releases/download/v0.1.0-alpha/injector.exe'


python_version = '3.8.9'

# These environment variables will get copied from the running process
copy_env = ('WINE', 'WINEPREFIX', 'WINEARCH', 'WINEESYNC', 'WINEFSYNC')


def get_idx_or(myList, idx, default=None):
    try:
        return myList[idx]
    except IndexError:
        return default

class Injector():
    def __init__(self, winebin):
        self.winebin = winebin
        self.basepath = os.path.dirname(os.path.abspath(__file__))
        if injector_use_binary:
            self.fullpath = os.path.join(self.basepath, injector_binary)
        else:
            self.fullpath = os.path.join(self.basepath, injector_script)
        self.psub = None

    def check_python_installed(self):
        check = subprocess.run([self.winebin, python_executable, '--version'], stdout=subprocess.DEVNULL)
        if check.returncode == 0:
            return True
        # python not installed inside Wine
        return False

    def _attach_script(self):
        if injector_use_binary: return
        if not self.check_python_installed():
            print('Python not found inside WINEPREFIX, installing...')
            arch = '-amd64' if os.environ.get('WINEARCH', 'win32') == 'win64' else ''
            filename = f'python-{python_version}-{arch}.exe'
            url = f'https://www.python.org/ftp/python/{python_version}/python-{python_version}{arch}.exe'
            urllib.request.urlretrieve(url, filename)
            install = subprocess.run(f'{self.winebin} {filename} /quiet InstallAllUsers=0 PrependPath=1 Include_test=0', shell=True, stdout=subprocess.DEVNULL)
            if install.returncode:
                raise Exception('Installation failed. Setting your Windows version to Windows 10 may fix this, if it\' not set already')
            os.remove(filename)
            print('Installation finished')
            if not self.check_python_installed():
                raise Exception('Still can not find python. This is weird...')

        self.psub = subprocess.Popen(f'{self.winebin} {python_executable} {self.fullpath}', shell=True, stdin=subprocess.PIPE)

    def _attach_binary(self):
        if not injector_use_binary: return
        if not os.path.exists(self.fullpath):
            print('Downloading injector')
            urllib.request.urlretrieve(injector_download_url, self.fullpath)
            print('Download finished')
        self.psub = subprocess.Popen(f'{self.winebin} {self.fullpath}', shell=True, stdin=subprocess.PIPE)

    def attach(self):
        if not injector_use_binary:
            self._attach_script()
        else:
            self._attach_binary()

    def detach(self):
        for p in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
            cmd = p.info['cmdline']
            if not injector_use_binary:
                if get_idx_or(cmd, 0, '').endswith('python.exe') and get_idx_or(cmd, 1, '').endswith(injector_script):
                    p.send_signal(signal.SIGINT)
                    break
            else:
                if p.name().endswith(injector_binary):
                    p.send_signal(signal.SIGINT)
                    # don't break, there will be two processes

        self.psub.wait(timeout or None)

    def attached(self):
        if self.psub:
            return self.psub.poll() is None
        return False

class TimeoutException(Exception):
    pass

class Process:
    def __init__(self, name, alt=None):
        self.name = name
        self.alt = alt or name
        self.process = None

    def find(self):
        if (p := find_process_by_name(self.alt) or find_process_by_name(self.name)) :
            self.process = p
            return True
        return False

    def wait_for(self, tsleep=1, timeout=0):
        start = time.time()
        while not self.find():
            time.sleep(sleep_time)
            if timeout and time.time() - start > timeout:
                raise TimeoutException(f'Timeout while waiting for {self.name}')

    def __repr__(self):
        return self.name

def check_ssl_connect(host, port, verify=True):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port)) as sock:
            with ctx.wrap_socket(sock) as ssock:
                return True
    except:
        return False

def find_process_by_name(name):
    for p in psutil.process_iter(attrs=['pid', 'name']):
        if p.info['name'] == name:
            return p

def find_section(proc, name):
    for m in proc.memory_maps(grouped=False):
        if m.path.lower().endswith(name.lower()):
            return int(m.addr.split('-')[0], 16), m

if __name__ == '__main__':
    # hide backtrace
    if hide_backtrace:
        sys.tracebacklimit = None

    rclient = Process('RiotClientServices.exe', 'RiotClientServi') # some OSes shorten this name for some reason. Adjust this if the process doesn't get found
    lclient = Process('LeagueClient.exe')
    lclientux = Process('LeagueClientUx.exe')

    # Wait for RiotClientServices.exe
    print(f'Waiting for {rclient}')
    rclient.wait_for(tsleep=sleep_time, timeout=timeout)
    print(f'Found {rclient}: pid {rclient.process.pid}')

    # copy WINE environment
    wineenv = {k:v for k,v in rclient.process.environ().items() if k in copy_env}
    wineenv.setdefault('WINEDEBUG', '-all')
    winebin = wineenv.pop('WINE')
    os.environ.update(wineenv)
    if not winebin: raise Exception('Wine executable could not be determined')
    inj = Injector(winebin)

    # Wait for LeagueClient.exe
    print(f'Waiting for {lclient}')
    lclient.wait_for(tsleep=sleep_time, timeout=timeout)
    print(f'Found {lclient}: pid {lclient.process.pid}')

    # Wait for LeagueClientUx.exe
    print(f'Waiting for {lclientux}')
    start = time.time()
    while not lclientux.find():
        if not inj.attached():
            print('Attaching...')
            inj.attach()
        time.sleep(sleep_time)
        if timeout and time.time() - start > timeout:
            inj.detach()
            raise TimeoutException(f'Timeout while waiting for {lclientux}')
    print(f'Found {lclientux}: pid {lclientux.process.pid}')

    # Find app-port
    port_xarg = next(x for x in lclientux.process.cmdline() if '--app-port=' in x)
    port = port_xarg.split('=')[1]

    # Wait for SSL response on app-port
    print(f'Waiting for port {port}')
    start = time.time()
    while not check_ssl_connect('127.0.0.1', port, verify=False):
        if not inj.attached():
            print('Attaching...')
            inj.attach()
        time.sleep(sleep_time)
        if timeout and time.time() - start > timeout:
            inj.detach()
            raise TimeoutException(f'Timeout while waiting for SSL response')

    if inj.attached():
        print('Detaching...')
        inj.detach()
    else:
        print('Nothing to do')

    print('Done')
