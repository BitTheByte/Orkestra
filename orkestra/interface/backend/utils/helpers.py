import os
import io


def safe_read(path, line=None):
    filename = os.path.basename(path)
    if os.path.isfile(os.path.join(os.path.dirname(path), filename)):
        if line:
            return io.open(path, 'r', encoding='utf8').read().split("\n")[int(line)]
        return io.open(path, 'r', encoding='utf8').read()
    return -1
