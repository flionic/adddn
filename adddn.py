#!/usr/bin/env python3.7
import os
import subprocess

import bcrypt
import flask_sqlalchemy
from flask import Flask, render_template, flash, redirect, url_for, jsonify, request
from flask_login import LoginManager, logout_user, login_user, current_user, login_required
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy, BaseQuery
from sqlalchemy import inspect
from sqlalchemy.ext.serializer import Serializer
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
    ssl = db.Column(db.Boolean(), default=True)
    child = db.Column(db.Integer)

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
    return render_template('index.html', p_domains=Domains.query.filter_by(pid=0).all())


@app.route('/settings')
def page_settings():
    return render_template('settings.html')


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


@app.route('/add-domain', methods=['POST'])  # TODO: he want refactor
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
    # TODO: errors handler
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


@app.route('/scan', methods=['POST'])
@login_required
def find_nginx_conf():
    Domains.query.delete()
    db.session.commit()
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
    # TODO: добавлять в базу уровень поддомена без цифры?

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
        s = open('template.conf').read()
        s = s.replace('TEMPLATE_DOMAIN', domain)
        f = open(f"/etc/nginx/sites-enabled/{domain}.conf", 'w')
        f.write(s)
        f.close()

    subprocess.call('service nginx reload', shell=True)
    # nginx = subprocess.check_output(["service", "nginx", "restart"])

    # TODO: ping new domain for verify if
    # TODO: move it to function
    certbot = subprocess.call(f"certbot --nginx -n certonly --cert-name {domains_new[0]} -d {','.join(domains_new)}", shell=True, universal_newlines=True)
    if certbot == 0:
        for domain in domains_new:
            s = open('template_ssl.conf').read()
            s = s.replace('TEMPLATE_DOMAIN', domain)
            s = s.replace('CERT_NAME', domains_new[0])
            f = open(f"/etc/nginx/sites-enabled/{domain}.conf", 'w')
            f.write(s)
            f.close()
            prefix = 'https'

    find_nginx_conf()
    return '\n'.join([f"{prefix}://{d}/" for d in domains_new])


@app.route('/getDomains', methods=['GET', 'POST'])
@login_required
def domains_list():
    # TODO: мб кеш?
    return jsonify([d.serialize() for d in Domains.query.all()])


@app.route('/addDomain', methods=['GET', 'POST'])
@login_required
def add_domain():
    resp = dict()

    s = open('template.conf').read()
    s = s.replace('TEMPLATE_DOMAIN', request.json['domain'])
    f = open(f"/etc/nginx/sites-enabled/{request.json['domain']}.conf", 'w')
    f.write(s)
    f.close()

    # TODO: move it to function
    subprocess.call('service nginx reload', shell=True)

    certbot = subprocess.call(f"certbot --nginx -n certonly --cert-name {request.json['domain']} -d {request.json['domain']}", shell=True, universal_newlines=True)

    if certbot == 0:
        s = open('template_ssl.conf').read()
        s = s.replace('TEMPLATE_DOMAIN', request.json['domain'])
        s = s.replace('CERT_NAME', request.json['domain'])
        f = open(f"/etc/nginx/sites-enabled/{request.json['domain']}.conf", 'w')
        f.write(s)
        f.close()
        resp['ssl'] = True
    else:
        resp['ssl'] = False

    find_nginx_conf()
    resp['response'] = 1
    return jsonify(resp)


def init_app():
    db.create_all()
    # os.path.exists('main.db')


init_app()
