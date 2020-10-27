from flask import Flask, jsonify, send_from_directory, make_response, request, redirect

from orkestra.interface.backend.utils.jadx import Jadx
from orkestra.interface.backend.utils.tree import walk

from orkestra.interface.backend.utils.helpers import *
from orkestra.interface.backend.utils.java import *

from orkestra.debugger.orkdbg import Orkdbg
import orkestra.logger as logger
import os

ORKESTRA_OUTPUT_DIR = "output"
ORKESTRA_UPLOAD_DIR = "upload"
ORKESTRA_UI_DIR     = "orkestra/interface/frontend"

app = Flask(import_name='')
dbg = Orkdbg(bin_dir='bin')
breakpoints = {}


def default():
    resp = make_response(safe_read(f'{ORKESTRA_UI_DIR}/index.html'), 200)
    resp.headers['Content-type'] = "text/html"
    return resp


def index(path):
    return send_from_directory(ORKESTRA_UI_DIR, path)


def upload():
    uploaded_file = request.files['file']
    uploaded_file.filename = uploaded_file.filename.lower()
    if uploaded_file.filename != '':
        uploaded_file.save(f"{ORKESTRA_UPLOAD_DIR}/{os.path.basename(uploaded_file.filename)}")
        logger.info(f"uploaded file={uploaded_file.filename} path={uploaded_file.filename}")
    return redirect(f"/apk/{os.path.basename(uploaded_file.filename)}/decompile")


def tree(name):
    return jsonify(walk(f"{ORKESTRA_OUTPUT_DIR}/{os.path.basename(name)}/sources"))


def code(name, path):
    content = safe_read(f'{ORKESTRA_OUTPUT_DIR}/{name}/sources/{path}')
    if content == -1:
        return make_response('', 404)

    logger.info(f"requested file read on dir={name} path={path}")

    return (f"""
            <input id='workPackage' value='{name}' type='hidden'/>
            <input id='workFile' value='{name}/{path}' type='hidden'/>
            <input id='workClass' value='{path_to_class_name(path)}' type='hidden'/>
            <input id='workBP' value='{",".join(breakpoints.get(path_to_class_name(path), ""))}' type='hidden'/>
            <pre><code class='java'>{content}</code></pre>
        """)


def decompile(name):
    Jadx(f"{ORKESTRA_UPLOAD_DIR}/{name}").decompile()
    manifest = safe_read(f"{ORKESTRA_OUTPUT_DIR}/{name}/resources/AndroidManifest.xml")
    package = re.findall('package="(.*?)"', manifest)[0]

    logger.info(f"decompiled package={package} file={name}")
    return redirect(f"/?apk={name}&package={package}")


def debugger_sync():
    if len(dbg.method.invokes):
        result = dbg.method.invokes.pop(0)
        logger.info(f"received invoke {result}")
        return jsonify(result)
    return jsonify({})


def debugger_attach(package):
    if dbg.attach(package):
        logger.done(f"attached debugger to package={package}")
        return jsonify({"attached": True})
    return jsonify({"attached": False})


def debugger_status():
    return jsonify({"attached": bool(dbg.session)})


def debugger_detach(package):
    if dbg.detach():
        logger.done(f"detached debugger from package={package}")
        return jsonify({"detached": True})
    return jsonify({"detached": False})


def debugger_spawn(package):
    if dbg.spawn(package):
        logger.done(f"spawned package={package}")
        return jsonify({"spawned": True})
    logger.info(f"unable to spawn package={package}")
    return jsonify({"spawned": False})


def set_breakpoint(name, path, line):
    fullcode = safe_read(f"{ORKESTRA_OUTPUT_DIR}/{name}/sources/{path}")
    text = fullcode.split("\n")[int(line)]

    if not java_is_declaration(text):
        return jsonify({"added": False, "text": text})

    method, overloads = java_parse_declaration(text, fullcode)

    dbg.method.monitor(
        class_name=path_to_class_name(path),
        overloads=overloads,
        method=method,
    )
    logger.info(f"started monitoring Class={path_to_class_name(path)}, Method={method}, Overloads={overloads}")

    bp = breakpoints.get(path_to_class_name(path), [])
    bp.append(f"{line}/{path_to_class_name(path)}/{method}")
    breakpoints[path_to_class_name(path)] = bp

    return jsonify({
        "added": True,
        "class": path_to_class_name(path),
        "method": method,
        "overloads": overloads,
        "line": line,
        "text": text,
    })


def rm_breakpoint(name, path, line):
    fullcode = safe_read(f"{ORKESTRA_OUTPUT_DIR}/{name}/sources/{path}")
    text = fullcode.split("\n")[int(line)]

    if not java_is_declaration(text):
        return jsonify({"removed": False})

    method, overloads = java_parse_declaration(text, fullcode)
    breakpoints[path_to_class_name(path)].remove(f"{line}/{path_to_class_name(path)}/{method}")

    logger.info(f"stopped monitoring Class={path_to_class_name(path)}, Method={method}, Overloads={overloads}")

    return jsonify({
        "removed": dbg.method.detach(path_to_class_name(path), method, overloads),
        "class": path_to_class_name(path),
        "method": method,
        "overloads": overloads,
        "line": line,
        "text": text
    })


app.route(rule="/", methods=['GET'])(default)
app.route(rule="/<path:path>", methods=['GET'])(index)

app.route(rule="/breakpoint/<name>/<path:path>/<line>", methods=['GET'])(set_breakpoint)
app.route(rule="/breakpoint/<name>/<path:path>/<line>/remove", methods=['GET'])(rm_breakpoint)

app.route(rule="/debugger/<package>/spawn", methods=['GET'])(debugger_spawn)
app.route(rule="/debugger/<package>/attach", methods=['GET'])(debugger_attach)
app.route(rule="/debugger/<package>/detach", methods=['GET'])(debugger_detach)
app.route(rule="/debugger/status", methods=['GET'])(debugger_status)
app.route(rule="/debugger/sync", methods=['GET'])(debugger_sync)

app.route(rule="/apk/<name>/decompile", methods=['GET'])(decompile)
app.route(rule="/apk/<name>/files/<path:path>", methods=['GET'])(code)
app.route(rule="/apk/<name>/tree", methods=['GET'])(tree)
app.route(rule="/importAPK", methods=['POST'])(upload)
