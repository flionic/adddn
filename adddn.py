#!/usr/bin/env python3.7
import shutil

import bcrypt
import os

from flask import Flask, render_template, flash, redirect, url_for, jsonify, request
from flask_login import LoginManager, logout_user, login_user, current_user, login_required
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.contrib.fixers import ProxyFix

app = Flask(__name__, instance_relative_config=True)
basedir = os.path.abspath(os.path.dirname(__file__))
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.url_map.strict_slashes = False
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['APP_NAME'] = 'domain_gen'
app.config['APP_TITLE'] = 'Генератор конфигов'
app.config['VERSION'] = '0.0.1'
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', '7-DEV_MODE_KEY-7')

db_link = 'sqlite:///' + os.path.join(basedir, 'main.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_link
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['SESSION_TYPE'] = 'redis'
sess = Session(app)
login_manager = LoginManager(app)
login_manager.login_view = "users.login"


@login_manager.user_loader
def load_user(uid):
    return Settings.query.filter_by(key=uid).first()


@login_manager.unauthorized_handler
def unauthorized_handler():
    flash('Для этого действия требуется авторизация', 'error')
    return redirect(url_for('index'))


class Settings(db.Model):
    key = db.Column(db.String(24), primary_key=True, unique=True, nullable=False)
    value = db.Column(db.Text)
    desc = db.Column(db.Text)

    def __init__(self, key, value, desc=None):
        self.key = key
        self.value = value
        self.desc = desc if desc else key

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    @staticmethod
    def get_id():
        return 'username'

    def __repr__(self):
        return "'%s': '%s'" % (self.key, self.value)


class Domains(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pid = db.Column(db.Integer, default=0)
    name = db.Column(db.String(255), nullable=False)
    ssl = db.Column(db.Boolean(), default=True)
    child = db.Column(db.Integer, default=None)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<Domain(id='%s', pid='%s', name='%s', ssl='%s', child='%s')>" % (self.id, self.pid, self.name, self.ssl, self.child)


@app.route('/')
def page_index():
    settings = Settings.query.offset(2).all() if current_user.is_authenticated else None
    return render_template('index.html', settings=settings)


@app.route('/settings')
def page_settings():
    settings = Settings.query.offset(2).all() if current_user.is_authenticated else None
    return render_template('settings.html', settings=settings)


@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        flash('Вы уже авторизированы', 'warning')
        return redirect(url_for('index'))
    password = Settings.query.filter_by(key='password').first()
    # elif bcrypt.checkpw(str.encode(request.form['password']), str.encode(password.value)) is False:
    if bcrypt.checkpw(str.encode(request.form['password']), str.encode(password.value)) is False:
        flash('Неверный пароль', 'error')
    else:
        login_user(Settings.query.filter_by(key='username').first())
        flash(f'Авторизирован')
    return jsonify({'response': 1})


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/update-cfg', methods=['POST'])
@login_required
def update_settings():
    data = request.json
    for cfg in data:
        Settings.query.filter_by(key=cfg['name']).first().value = cfg['value']
    db.session.commit()
    return jsonify({"response": 1})


@app.route('/add-domain', methods=['POST'])
@login_required
def push_domain():
    print(request.json)
    # return jsonify({"error_msg": 'Не удалось авторизироваться в CloudFlare'}), 500

    s = open(Settings.query.filter_by(key='pd_cfg_path').first().value).read()
    # s = s.replace(Settings.query.filter_by(key='cf_zone_name').first().value, request.json['new_domain'])
    s = s.replace('TEMPLATE_DOMAIN', f"{request.json['domain_name']}.{Settings.query.filter_by(key='cf_zone_name').first().value}")
    f = open(f"/etc/nginx/sites-enabled/{request.json['domain_name']}.{Settings.query.filter_by(key='cf_zone_name').first().value}.conf", 'w')
    f.write(s)
    f.close()
    # shutil.copy('/etc/nginx/sites-enabled/link.conf', '/var/www/adddn/')
    # TODO: SSL CERTBOT !!! # certbot --nginx -n certonly --cert-name adddn.ml -d adddn.ml,1.testadn.ml,2.testadn.ml
    import subprocess
    subprocess.call('service nginx reload', shell=True)

    import CloudFlare
    email = Settings.query.filter_by(key='cf_email').first().value
    token = Settings.query.filter_by(key='cf_token').first().value
    certtoken = Settings.query.filter_by(key='cf_ca_token').first().value
    cf = CloudFlare.CloudFlare(email=email, token=token, certtoken=certtoken)
    zone_id = Settings.query.filter_by(key='cf_zone_id').first().value
    dns_test = {'name': request.json['domain_name'], 'type': 'A', 'content': request.json['domain_ip'], 'proxied': True}
    cf.zones.dns_records.post(zone_id, data=dns_test)

    return jsonify({"response": 1})


def init_app():
    db.create_all()
    # os.path.exists('main.db')


init_app()

