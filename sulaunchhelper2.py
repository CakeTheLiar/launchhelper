#!/usr/bin/env python3

import frida
import socket
import ssl
import psutil
import time
import subprocess
import sys

"""
    requires psutil, frida (pip install psutil frida)
    
    suLaunchhelper2 will try to lauch the League of Legends client by instrumenting frida (https://frida.re/)
    This version requires sudo or `sysctl kernel.yama.ptrace_scope=0`.
    It will launch frida directly from outside of wine.
"""

WINEDUMP = 'winedump' # path to winedump, does not necessarily need to be the same version as wine

SELECT_SIGNATURE = "'long', ['long', 'pointer', 'pointer', 'pointer'], 'stdcall'" # return type, [arg types...], abi

sleep_time = 1
timeout = 0 # 0 to disable

hide_backtrace = True


class FridaWrapper():
    def __init__(self, process, module=None, export=None, position=None, signature=None):
        self.session = None
        self.process = process
        self.module = module
        self.export = export
        self.position = position
        self.signature = signature

    def get_location(self):
        if self.module and self.export:
            return f"Process.getModuleByName('{self.module}').getExportByName('{self.export}')"
        if self.position and self.signature:
            return f"new NativeFunction(ptr({hex(self.position)}), {self.signature})"

    def attach(self):
        if self.session: return
        self.session = frida.attach(self.process)


        script = self.session.create_script("""
        Interceptor.attach(
            """ + self.get_location() + """, {
                onEnter: function(args) {
                    args[4].writeInt(0x0);
                }
            }
        );
        """)
        script.load()

    def detach(self):
        if not self.session: return
        script = self.session.create_script("Interceptor.detachAll();")
        script.load()
        self.session.detach()
        self.session = None

    def attached(self):
        return self.session is not None

class TimeoutException(Exception):
    pass

class Process:
    def __init__(self, name, internal=None):
        self.name = name
        self.internal = internal or name
        self.process = None

    def find(self):
        if p := find_process_by_name(self.internal):
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

def get_dll_exports(dll):
    exports = subprocess.run(['winedump', '-j', 'export', dll], stdout=subprocess.PIPE).stdout
    exports = str(exports, 'utf-8')
    exports = exports.split('\n')
    exports = exports[19:-3] # everything before this is just the pretext
    exports = [Symbol(sym[0], sym[1], sym[2]) for sym in [e.strip().split() for e in exports]]
    return exports

def find_dll_export(dll, export):
    exports = get_dll_exports(dll)
    for e in exports:
        if e.name == export:
            return e

if __name__ == '__main__':
    # hide backtrace
    if hide_backtrace:
        sys.tracebacklimit = None

    rclient = Process('RiotClientServices.exe', 'RiotClientServi')
    lclient = Process('LeagueClient.exe')
    lclientux = Process('LeagueClientUx.exe')

    # Wait for RiotClientServices.exe
    print(f'Waiting for {rclient}')
    rclient.wait_for(tsleep=sleep_time, timeout=timeout)
    print(f'Found {rclient}: pid {rclient.process.pid}')

    base, module = find_section(rclient.process, 'ws2_32.dll')
    exp_select = find_dll_export(module.path, 'select')

    # Wait for LeagueClient.exe
    print(f'Waiting for {lclient}')
    lclient.wait_for(tsleep=sleep_time, timeout=timeout)
    print(f'Found {lclient}: pid {lclient.process.pid}')

    f = FridaWrapper(rclient.process.pid, position = base + exp_select.offset, signature = SELECT_SIGNATURE)

    # Wait for LeagueClientUx.exe
    print(f'Waiting for {lclientux}')
    start = time.time()
    while not lclientux.find():
        if not f.attached():
            print('Attaching...')
            f.attach()
        time.sleep(sleep_time)
        if timeout and time.time() - start > timeout:
            f.detach()
            raise TimeoutException(f'Timeout while waiting for {lclientux}')
    print(f'Found {lclientux}: pid {lclientux.process.pid}')

    # Find app-port
    port_xarg = next(x for x in lclientux.process.cmdline() if '--app-port=' in x)
    port = port_xarg.split('=')[1]

    # Wait for SSL response on app-port
    print(f'Waiting for port {port}')
    start = time.time()
    while not check_ssl_connect('127.0.0.1', port, verify=False):
        if not f.attached():
            print('Attaching...')
            f.attach()
        time.sleep(sleep_time)
        if timeout and time.time() - start > timeout:
            f.detach()
            raise TimeoutException(f'Timeout while waiting for SSL response')

    if f.attached():
        print('Detaching...')
        f.detach()
    else:
        print('Nothing to do')

    print('Done')