import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
  SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
  SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'app.db')
  SQLALCHEMY_TRACK_MODIFICATIONS = False

  MAIL_SERVER = (os.environ.get('MAIL_SERVER') or 'localhost')
  MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
  MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
  MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
  MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
  ADMINS = ['admar@familieschoonen.nl']

  UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'files'
  MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH') or 16*1024*1024)

  SERVERNAME = os.environ.get('SERVERNAME')
