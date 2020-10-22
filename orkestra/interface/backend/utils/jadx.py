import orkestra.logger as logger
import subprocess
import os

JADX_BIN = os.path.dirname(__file__) + "/../jadx/bin/jadx.bat"


class Jadx(object):
    def __init__(self, inputfile):
        self.input = inputfile

    def decompile(self):
        cmd = f"{JADX_BIN} {self.input} -d output/{os.path.basename(self.input)}"
        logger.info(f"starting jadx using command: {cmd} ")
        subprocess.check_call(cmd)
