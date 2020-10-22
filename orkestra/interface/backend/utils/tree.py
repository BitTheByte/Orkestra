from glob import glob
import os


def jsTree(text, childrens=[], icon=""):
    return {"text": text, "parent": "#", "children": childrens, "icon": icon}


def walk(target):
    target = target.replace("\\", "/")
    filesTree = []
    for path in glob(f"{target}/*"):
        if os.path.isfile(path):
            if path.split(".")[-1] == "java":
                filesTree.append(jsTree(text=os.path.basename(path), icon="/assets/img/java-16x16.png"))
        if os.path.isdir(path):
            filesTree.append(
                jsTree(text=os.path.basename(path), childrens=walk(os.path.join(target, os.path.basename(path)))))
    return filesTree
