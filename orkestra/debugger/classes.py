class ClassHooker:
    def __init__(self, session):
        self.session = session
        self.script = open("scripts/describe_class.js", "r").read()
        self.descriptions = {}

    def result(self, message, payload):
        if message["type"] != "send": return
        payload = message["payload"]
        self.descriptions[payload["class"]] = payload

    def describe(self, class_name):
        if class_name in self.descriptions:
            return self.descriptions[class_name]

        script = self.session.create_script(self.script.replace("@ORKESTRA_PARAM_0@", class_name))
        script.on("message", self.result)
        script.load()

        while not class_name in self.descriptions:
            # TODO: this is not safe and can hang forever
            pass

        return self.descriptions[class_name]
