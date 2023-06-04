import orkestra.logger as logger
from tqdm.auto import tqdm
import subprocess
import functools
import requests
import pathlib
import frida
import glob
import lzma
import os
import re
import shutil

class Frida(object):
    def __init__(self, bin_dir):
        self.__bin_dir = bin_dir

    def __download(self, url, filename):
        d = lzma.LZMADecompressor()
        r = requests.get(url, stream=True, allow_redirects=True)
        if r.status_code != 200:
            r.raise_for_status()
            raise RuntimeError(f"Request to {url} returned status code {r.status_code}")
        file_size = int(r.headers.get('Content-Length', 0))

        path = pathlib.Path(filename.replace(".xz", "")).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        desc = "(Unknown total file size)" if file_size == 0 else ""
        r.raw.read = functools.partial(r.raw.read, decode_content=True)
        with tqdm.wrapattr(r.raw, "read", total=file_size, desc=desc) as r_raw:
            with path.open("wb") as f:
                f.write(d.decompress(r_raw.read()))

        return path

    def download_files(self):
        if not os.path.isdir(self.__bin_dir):
            logger.info(f"unable to found {self.__bin_dir} directory .. is this the first run?")
            os.mkdir(self.__bin_dir)
        else:
            logger.info(f"found servers directory on {self.__bin_dir}")
            return  # FIXME

        logger.info(f"downloading required server files to {self.__bin_dir}")

        response = requests.get("https://github.com/frida/frida/releases/latest").text
        urls = re.findall('<a href=\"/frida/frida/releases/download/.*?\"', response)
        servers = ["https://github.com" + re.findall('"(.*)"', url)[0] for url in urls if
                   url.find("frida-server") != -1 and url.find("android") != -1]

        for server in servers:
            self.__download(server, f"{self.__bin_dir}/" + server.split("/")[-1])

    def get_usb_device(self):
        subprocess.check_call("adb root", shell=True)
        self._kill_all()
        for server in glob.glob(f"{self.__bin_dir}/*"):
            server = self._push_tmp_file(server)
            self._chmod_file(server, 777)
            self._run_as_daemon(server)

            if self.can_comunicate_with_server():
                device = frida.get_usb_device()
                logger.done(f"we are able to communicate with server at {server}, device: {device}")
                return device

            self._kill_all()
        logger.error("unable to find suitable server for this target")
        return None

    def _push_tmp_file(self, file_path):
        tmp_path = f"/data/local/tmp/{os.path.basename(file_path)}"
        temp_files = subprocess.check_output('adb shell "ls /data/local/tmp"', shell=True).decode()
        subprocess.check_call(f"adb push {file_path} {tmp_path}", shell=True)
        return tmp_path

    def _chmod_file(self, file_path, mode=777):
        subprocess.check_call(f'adb shell "chmod {mode} {file_path}"', shell=True)

    def _run_as_daemon(self, server_path):
        subprocess.check_call(f'adb shell ".{server_path} -D &"', shell=True)

    def _kill_all(self):
        try:
            subprocess.check_call('adb shell "kill -9 `pgrep -i \'frida\'` &> /dev/null"', shell=True)
        except:
            pass

    def can_comunicate_with_server(self):
        try:
            session = frida.get_usb_device()
            processes = session.enumerate_processes()
            session.attach("com.google.android.gms")
            return True
        except Exception as e:
            pass
            #print(str(e))
        return False
