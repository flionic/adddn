from adddn import app
from setproctitle import setproctitle
import cli
cli.register(app)
# TODO: rename project to domgen

if __name__ == "__main__":
    setproctitle(f'{app.config["APP_NAME"]}')
    app.run(host='0.0.0.0', port=23044, debug=True)
