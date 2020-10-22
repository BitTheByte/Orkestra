from orkestra.debugger.methods import MethodHooker
from orkestra.debugger.fridaa import Frida
import orkestra.logger as logger


class Orkdbg:
    def __init__(self, bin_dir):
        self.session = None
        frida = Frida(bin_dir)
        frida.download_files()
        self.frida = frida.get_usb_device()
        self.method = MethodHooker(self.session)

    def spawn(self, package):
        pid = self.frida.spawn(package)
        self.session = self.frida.attach(pid)
        self.frida.resume(pid)
        self.method = MethodHooker(self.session)
        return True

    def attach(self, package):
        try:
            if not self.session:
                self.session = self.frida.attach(package)
                self.method = MethodHooker(self.session)
                return True
            return False
        except Exception as e:
            logger.error(str(e))
            return False

    def detach(self):
        try:
            if self.session:
                self.session.detach()
                self.session = None
                return True
            return False
        except Exception as e:
            logger.error(str(e))
            return False