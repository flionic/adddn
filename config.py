import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, 'settings.env'))


class Config(object):
    APP_NAME = os.environ.get('APP_NAME') or 'flionic_flask'
    # SERVER_NAME = os.environ.get('SERVER_NAME') or 'localhost'
    # APPLICATION_ROOT = os.environ.get('APPLICATION_ROOT')
    APP_TITLE = os.environ.get('APP_TITLE') or 'Генератор доменов'
    VERSION = os.environ.get('VERSION') or '0.0.1'
    WORKERS = os.environ.get('WORKERS') or 1

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'main.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT')
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['your-email@example.com']
    LANGUAGES = ['ru', 'ru']
    # MS_TRANSLATOR_KEY = os.environ.get('MS_TRANSLATOR_KEY')
    # ELASTICSEARCH_URL = os.environ.get('ELASTICSEARCH_URL')
    SESSION_TYPE = os.environ.get('SESSION_TYPE') or 'redis'
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'
