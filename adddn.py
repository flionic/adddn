#!/usr/bin/env python3.7
import os

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.contrib.fixers import ProxyFix

app = Flask(__name__, instance_relative_config=True)
basedir = os.path.abspath(os.path.dirname(__file__))
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.url_map.strict_slashes = False
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['APP_NAME'] = 'adddn'
app.config['APP_TITLE'] = 'Add domains'
app.config['VERSION'] = '0.0.1'
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', '7-DEV_MODE_KEY-7')


@app.route('/')
def index():
    return render_template('index.html')
