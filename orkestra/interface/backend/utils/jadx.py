import orkestra.logger as logger
import subprocess
import os


JADX_BIN = "orkestra\\interface\\backend\\jadx\\bin\\jadx.bat" if os.name =="nt" else "orkestra/interface/backend/jadx/bin/jadx"


class Jadx(object):
    def __init__(self, inputfile):
        self.input = inputfile

    def decompile(self):
        if os.name != "nt": subprocess.check_call(f"chmod +x {JADX_BIN}", shell=True)
        cmd = f'{JADX_BIN} "{self.input}" -d "output/{os.path.basename(self.input)}"'
        logger.info(f"starting jadx using command: {cmd} ")
        subprocess.check_call(cmd,shell=True)
