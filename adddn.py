#!/usr/bin/env python3.7
import os
import subprocess
from datetime import datetime
from time import sleep, time

import bcrypt
import flask_sqlalchemy
import requests
from flask import Flask, render_template, flash, redirect, url_for, jsonify, request
from flask_login import LoginManager, logout_user, login_user, current_user, login_required
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy, BaseQuery
from sqlalchemy import inspect
from sqlalchemy.ext.serializer import Serializer
from werkzeug.contrib.fixers import ProxyFix
from telegram import Bot

app = Flask(__name__, instance_relative_config=True)
basedir = os.path.abspath(os.path.dirname(__file__))
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
app.url_map.strict_slashes = False
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['APP_NAME'] = 'domain_gen'
app.config['APP_TITLE'] = 'Генератор конфигов'
app.config['VERSION'] = '1.0.1'
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY', '7-DEV_MODE_KEY-7')

db_link = 'sqlite:///' + os.path.join(basedir, 'main.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_link
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['SESSION_TYPE'] = 'redis'
sess = Session(app)
login_manager = LoginManager(app)
login_manager.login_view = "users.login"
bot = None


@login_manager.user_loader
def load_user(uid):
    return Settings.query.filter_by(key=uid).first()


@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Для этого действия требуется авторизация', 403


class Serializer(object):
    def serialize(self, include={}, exclude=[], only=[]):
        serialized = {}
        for key in inspect(self).attrs.keys():
            to_be_serialized = True
            value = getattr(self, key)
            if key in exclude or (only and key not in only):
                to_be_serialized = False
            elif isinstance(value, BaseQuery):
                to_be_serialized = False
                if key in include:
                    to_be_serialized = True
                    nested_params = include.get(key, {})
                    value = [i.serialize(**nested_params) for i in value]

            if to_be_serialized:
                serialized[key] = value

        return serialized


class SerializableBaseQuery(BaseQuery):
    def serialize(self, include={}, exclude=[], only=[]):
        return [m.serialize(include, exclude, only) for m in self]


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


class Domains(db.Model, Serializer):
    id = db.Column(db.Integer, primary_key=True)
    pid = db.Column(db.Integer)
    name = db.Column(db.String(255), nullable=False)
    ssl = db.Column(db.Boolean(), default=None)
    child = db.Column(db.Integer)
    hide = db.Column(db.Boolean(), default=False)
    ban = db.Column(db.Boolean(), default=False)
    check_time = db.Column(db.Integer)

    def __init__(self, name):
        self.name = name
        level = name.count('.')
        parent = ".".join(name.rsplit('.', 2)[1:])
        d_parent = Domains.query.filter_by(name=parent).first()
        self.pid = 0 if level == 1 else d_parent.id if d_parent else -1
        self.child = len(Domains.query.filter_by(pid=self.id).all())

    def __repr__(self):
        return '<Domains(id=%s, pid=%s, name=%s, ssl=%s, child=%s)>' % (self.id, self.pid, self.name, self.ssl, self.child)

    @property
    def computed_field(self):
        return 'this value did not come from the db'

    def keys(self):
        return super().keys() + ['computed_field']


def d_sort(e):
    return e.count('.')


@app.route('/')
def page_index():
    if Settings.query.filter_by(key='installed').first() is None:
        return redirect(url_for('act_install'))
    p_domains = Domains.query.filter_by(pid=0).filter_by(hide=False).all()
    geos = open('geos.txt').read().split('\n')
    return render_template('index.html', p_domains=p_domains, geos=geos)


@app.route('/settings')
def page_settings():
    return render_template('settings.html', upd_time=datetime.fromtimestamp(int(Settings.query.filter_by(key='domains_checked').first().value)))


@app.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        flash('Вы уже авторизированы', 'warning')
        return redirect(url_for('index'))
    password = Settings.query.filter_by(key='password').first()
    # elif bcrypt.checkpw(str.encode(request.form['password']), str.encode(password.value)) is False:
    if bcrypt.checkpw(str.encode(request.form['password']), password.value) is False:
        flash('Неверный пароль', 'error')
    else:
        login_user(Settings.query.filter_by(key='username').first())
        flash(f'Авторизирован')
    return jsonify({'response': 1})


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('page_index'))


@app.route('/actInstall', methods=['GET', 'POST'])
def act_install():
    if Settings.query.filter_by(key='installed').first():
        return redirect(url_for('page_index')), 302
    if request.method == 'GET':
        return render_template('register.html')
    if request.method == 'POST':
        installed = Settings('installed', datetime.now())
        username = Settings('username', 'admin')
        password = Settings('password', bcrypt.hashpw(str.encode(request.form['password']), bcrypt.gensalt()))
        db.session.add(installed)
        db.session.add(username)
        db.session.add(password)
        db.session.commit()
        login_user(Settings.query.filter_by(key='username').first())
        return jsonify({"status": "registered"})


@app.route('/update-cfg', methods=['POST'])
@login_required
def update_settings():
    data = request.json
    for cfg in data:
        Settings.query.filter_by(key=cfg['name']).first().value = cfg['value']
    db.session.commit()
    return jsonify({"response": 1})


@app.route('/scan', methods=['POST'])
@login_required
def find_nginx_conf():
    # Domains.query.delete()
    # db.session.commit()
    domains = subprocess.check_output(["sh", "/var/www/adddn/nxcfgs_get.sh"]).decode()[:-1].split('\n')
    domains.sort(key=d_sort)
    for d in domains:
        if Domains.query.filter_by(name=d).first() is None:
            d_new = Domains(d)  # TODO находить сертификат LE
            db.session.add(d_new)
            db.session.commit()

    domains = Domains.query.all()
    for d in domains:
        d.child = len(Domains.query.filter_by(pid=d.id).all())
    db.session.commit()

    subprocess.call('service nginx reload', shell=True)

    # TODO: check ssl and gen ssl btn

    return jsonify({'response': 1})


@app.route('/generateDomains', methods=['GET', 'POST'])  # nxcfgen
@login_required
def domain_generator():
    start_index = 0
    domains_new = list()
    prefix = 'http'
    # TODO: добавлять в базу уровень поддомена без цифры? И путь конфига

    d = Domains.query.filter_by(id=int(request.args.get('domain_id'))).first()
    if d.child > 0:
        cd = Domains.query.filter_by(pid=int(request.args.get('domain_id'))).order_by(Domains.id.asc())
        for i in cd.all():
            if request.args.get('geo') in i.name.split('.', 2)[0]:
                index = (i.name.split('.', 2)[0]).replace(request.args.get('geo'), '')
                index = 0 if index is '' else int(index)
                start_index = index if index > start_index else start_index
                cd = i
        if isinstance(cd, flask_sqlalchemy.BaseQuery):
            cd = cd.first()
        else:
            start_index += 1
        d_parent = ".".join(cd.name.rsplit('.', 2)[1:])
    else:
        d_parent = d.name

    for i in range(start_index, int(request.args.get('num')) + start_index):
        domains_new.append(f"{request.args.get('geo')}{i if i > 0 else ''}.{d_parent}")

    for domain in domains_new:
        with open('template.conf', 'r') as file:
            conf = file.read()
        conf = conf.replace('TEMPLATE_DOMAIN', domain)
        with open(f"/etc/nginx/sites-available/{domain}", 'w') as file:
            file.write(conf)
        subprocess.call(f"ln -s /etc/nginx/sites-available/{domain} /etc/nginx/sites-enabled/{domain}", shell=True)

    subprocess.call('service nginx reload', shell=True)
    # nginx = subprocess.check_output(["service", "nginx", "restart"])

    # TODO: ping new domain for verify if
    # TODO: move it to function
    certbot = subprocess.call(f"certbot -n certonly --webroot -w /var/www/bestplace.live --cert-name {domains_new[0]} -d {','.join(domains_new)}", shell=True, universal_newlines=True)
    if certbot == 0:
        for domain in domains_new:
            with open('template.conf', 'r') as file:
                conf = file.read()
            conf = conf.replace('TEMPLATE_DOMAIN', domain)
            conf = conf.replace('CERT_NAME', domains_new[0])
            conf = conf.replace('#NOSLL', '').replace('listen 80;', '')
            with open(f"/etc/nginx/sites-available/{domain}", 'w') as file:
                file.write(conf)
            prefix = 'https'

    find_nginx_conf()
    return '\n'.join([f"{prefix}://{d}/" for d in domains_new])


@app.route('/getDomains', methods=['GET', 'POST'])
@login_required
def domains_list():
    # TODO: мб кеш?
    return jsonify([d.serialize() for d in Domains.query.filter_by(hide=False).all()])
    # return jsonify([d.serialize() for d in Domains.query.filter_by(pid=0).all()])


@app.route('/addDomain', methods=['GET', 'POST'])
@login_required
def add_domain():
    resp = dict()

    sd = Domains.query.filter_by(name=request.json['domain']).first()
    if sd:
        sd.hide = False
        db.session.commit()

    with open('template.conf', 'r') as file:
        conf = file.read()
    conf = conf.replace('TEMPLATE_DOMAIN', request.json['domain'])
    with open(f"/etc/nginx/sites-available/{request.json['domain']}", 'w') as file:
        file.write(conf)
    subprocess.call(f"ln -s /etc/nginx/sites-available/{request.json['domain']} /etc/nginx/sites-enabled/{request.json['domain']}", shell=True)

    # TODO: move it to function
    subprocess.call('service nginx reload', shell=True)

    certbot = subprocess.call(f"certbot --nginx -n certonly --webroot -w /var/www/bestplace.live --cert-name {request.json['domain']} -d {request.json['domain']}", shell=True, universal_newlines=True)

    if certbot == 0:
        conf = conf.replace('#NOSLL', '').replace('CERT_NAME', request.json['domain'])
        with open(f"/etc/nginx/sites-available/{request.json['domain']}", 'w') as file:
            file.write(conf)
        resp['ssl'] = True
    else:
        resp['ssl'] = False

    find_nginx_conf()
    resp['response'] = 1
    return jsonify(resp)


@app.route('/removeDomains', methods=['POST'])
@login_required
def remove_domains():
    for d in request.json:
        # Domains.query.filter_by(id=d['id']).delete()
        Domains.query.filter_by(id=d['id']).first().hide = True
    db.session.commit()
    return jsonify({'response': 1})


@app.route('/saveConfig', methods=['POST'])
@login_required
def save_config():
    if 'key' not in request.json:
        return jsonify({'error_msg': 'need key'}), 500
    s = Settings.query.filter_by(key=request.json['key']).first()
    if s is None:
        return jsonify({'error_msg': 'invalid key'}), 500
    s.value = request.json['value']
    db.session.commit()
    init_app()
    return jsonify({'response': 1})


def check_domains():
    print('Check domains..')
    # TODO: filter by banned
    domains = Domains.query.filter_by(pid=0).filter_by(hide=False).filter_by(ban=False).all()
    url = 'https://graph.facebook.com'
    data = {
        'access_token': app.config['FB_TOKEN'],
        'scrape': True
    }
    # TODO: collect limit errors
    for d in domains:
        if d.check_time is None or int(time()) > d.check_time + (60 * 15):
            data['id'] = 'https://' + d.name
            r = requests.post(url, data=data)
            # print(r.json())
            if 'error' in r.json() and r.json()['error']['code'] == 368:
                bot.send_message(chat_id=app.config['TG_CHAT'], text=f"⚠️ BAN\n{d.name}") if bot else None
                print(f"⚠ BAN {d.name}")
                d.ban = True
            else:
                d.ban = False
            app.config['FB_CHECKER'] = r.json()
            d.check_time = int(time())
            db.session.commit()
    Settings.query.filter_by(key='domains_checked').first().value = int(time())
    db.session.commit()


def fb_checker():
    print('FbChecker enabled')
    while True:
        if int(time()) > int(Settings.query.filter_by(key='domains_checked').first().value) + (60 * 10):
            check_domains()
        sleep(60)


def init_app():
    # TODO: First install Settings: tg_chat, tg_token, fb_token, domains_checked
    tg_chat = Settings.query.filter_by(key='tg_chat').first().value
    tg_token = Settings.query.filter_by(key='tg_token').first().value
    fb_token = Settings.query.filter_by(key='fb_token').first().value

    app.config['TG_CHAT'] = tg_chat if tg_chat else ''
    app.config['TG_TOKEN'] = tg_token if tg_chat else ''
    app.config['FB_TOKEN'] = fb_token if fb_token else ''

    # TODO: app.config['errors'] = [{'name': '', 'message': ''}]
    global bot
    try:
        bot = Bot(app.config['TG_TOKEN'])
        app.config['TG_BOT'] = 'connected'
    except Exception as e:
        app.config['TG_BOT'] = e
        print(e)

    # if True not in [i.isDaemon() for i in threading.enumerate()]:
    #     a = threading.Thread(target=fb_checker)
    #     a.setName('FbChecker')
    #     a.start()
    # print(threading.enumerate())


db.create_all()
init_app()
