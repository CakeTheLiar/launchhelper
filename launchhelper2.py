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

sleep_time = 1
timeout = 0 # 0 to disable

hide_backtrace = True

injector_file = 'injector.py'

class Injector():
    def __init__(self, winebin):
        self.winebin = winebin
        self.psub = None

    def check_python_installed(self):
        check = subprocess.run([self.winebin, 'python', '--version'], stdout=subprocess.DEVNULL)
        if check.returncode == 0:
            return True
        # python not installed inside Wine
        return False

    def attach(self):
        if not self.check_python_installed():
            print('Python not found inside WINEPREFIX, installing...')
            arch = '-amd64' if os.environ.get('WINEARCH', 'win32') == 'win64' else ''
            version = '3.10.2'
            filename = f'python-{version}-{arch}.exe'
            url = f'https://www.python.org/ftp/python/{version}/python-{version}{arch}.exe'
            urllib.request.urlretrieve(url, filename)
            subprocess.run(f'{self.winebin} {filename} /quiet InstallAllUsers=0 PrependPath=1 Include_test=0', shell=True, stdout=subprocess.DEVNULL)
            os.remove(filename)
            print('Installation finished')

        self.psub = subprocess.Popen(f'{self.winebin} python {injector_file}', shell=True, stdin=subprocess.PIPE)

    def detach(self):
        for p in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
            cmd = iter(p.info['cmdline'])
            if next(cmd, '').endswith('python.exe') and next(cmd, '').endswith(injector_file):
                p.send_signal(signal.SIGINT)
                break
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

class Symbol:
    def __init__(self, offset, position, name):
        self.offset = offset if type(offset) == int else int(offset, 16)
        self.position = int(position)
        self.name = name
    
    def __repr__(self):
        return f'Symbol(offset={hex(self.offset)}, position={self.position}, name=\'{self.name}\')'

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
    wineenv = {k:v for k,v in rclient.process.environ().items() if k in ('WINE', 'WINEPREFIX', 'WINEARCH')}
    wineenv['WINEDEBUG'] = '-all'
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