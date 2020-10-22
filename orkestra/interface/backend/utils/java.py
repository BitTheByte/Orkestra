import re

JAVA_FN_REGEX = '(public|private|protected|static|final|native|synchronized|abstract|transient)+\s+([\$_\w\<\>\w\s\[\]]*)\s+([\$_\w]+)([^\)]*\)?\s*)'


def java_is_declaration(line):
    conditions = [
        line[-1] == "{",
    ]
    for c in conditions:
        if c == False:
            return False
    return True


def java_extend_type(name, fullcode):
    imports = re.findall("import\s*(.*)\;", fullcode)
    for impt in imports:
        if name in impt:
            return impt
    return name


def java_parse_declaration(line, fullcode):
    scope, rettype, name, args = re.findall(JAVA_FN_REGEX, line)[0]
    args = args.strip().replace("(", "").replace(")", "")
    args = [arg for arg in args.strip().split(",") if arg.strip()]
    overloads = []
    if len(args) == 0:
        return name, overloads
    for arg in args:
        argtype, argname = arg.strip().split(" ")
        overloads.append(java_extend_type(argtype, fullcode))
    return name, overloads


def path_to_class_name(path):
    clsname = path.replace("/", ".")
    clsname = clsname.replace("\\", ".")
    clsname = ".".join(clsname.split(".")[:-1])
    return clsname
