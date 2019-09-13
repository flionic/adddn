from adddn import app
import cli
cli.register(app)

bind = f"unix:/var/run/{app.config['APP_NAME']}/{app.config['APP_NAME']}.sock"
workers = app.config['WORKERS']
pidfile = f"/var/run/{app.config['APP_NAME']}/{app.config['APP_NAME']}.pid"
accesslog = '-'
errorlog = '-'
proc_name = app.config['APP_NAME']
# umask = 0o07
daemon = True
enable_stdio_inheritance = True

# TODO: rename project to domgen
