from orkestra.interface.backend.server import app
import logging
import sys
import os

cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *x: None
app.logger.disabled = True
logging.getLogger('werkzeug').disabled = True
os.environ['WERKZEUG_RUN_MAIN'] = 'true'
app.run(host="0.0.0.0", port=8080, debug=False)