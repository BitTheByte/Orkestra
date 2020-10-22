import orkestra.logger as logger

class MethodHooker:
    def __init__(self, session):
        self.session = session
        self.scripts_session = {}
        self.script = open("scripts/monitor_method.js", "r").read()
        self.invokes = []

    def result(self, message, payload):
        self.invokes.append({"message": message, "payload": payload, "from": "jmethod"})

    def detach(self, jclass, method, overloads):
        session_name = f"{jclass}.{method}({overloads})"
        scripts = self.scripts_session.get(session_name, None)
        if scripts is None or scripts == []:
            return False
        for script in scripts:
            try:
                script.unload()
            except:
                pass
            scripts.remove(script)
        return True

    def monitor(self, class_name, method, overloads):
        script = self.script

        args = ','.join([f"param_{n}" for n in range(len(overloads))])
        if len(overloads) > 0:
            _overloads = ",".join([f'"{overload}"' for overload in overloads])
        else:
            _overloads = ""
        script = script.replace("@ORKESTRA_PARAM_ARGS@", args)
        script = script.replace("@ORKESTRA_PARAM_METHOD@", method)
        script = script.replace("@ORKESTRA_PARAM_JCLASS@", class_name)
        script = script.replace("@ORKESTRA_PARAM_OVERLOADS@", _overloads)

        script = self.session.create_script(script)
        script.on("message", self.result)
        script.load()

        session_name = f"{class_name}.{method}({overloads})"

        if self.scripts_session.get(session_name, None) is None:
            self.scripts_session[session_name] = []
        self.scripts_session[session_name].append(script)
