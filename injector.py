import signal
import sys
import time

try:
    import frida
except:
    import subprocess
    print('frida not found, installing...')
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'frida'])
    print('install finished')
    import frida

SELECT_SIGNATURE = "'long', ['long', 'pointer', 'pointer', 'pointer'], 'stdcall'" # return type, [arg types...], abi
timeout = 1 * 60

class TimeoutException(Exception):
    pass

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

if __name__ == '__main__':
    f = FridaWrapper('RiotClientServices.exe', module='WS2_32.dll', export='select')

    def sigterm_handler(_signo, _stack_frame):
        f.detach()
        sys.exit(0)

    signal.signal(signal.SIGTERM, sigterm_handler)
    signal.signal(signal.SIGINT, sigterm_handler)
    signal.signal(signal.SIGBREAK, sigterm_handler)

    start = time.time()
    f.attach()
    while f.attached():
        time.sleep(1)
        if timeout and time.time() - start > timeout:
            raise TimeoutException('Timeout during injection')