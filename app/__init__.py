from flask import Flask, url_for, render_template, redirect, url_for
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import logging
from logging.handlers import SMTPHandler, RotatingFileHandler
import os
from flask_mail import Mail
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
import sys

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)

migrate = Migrate(app, db)

login = LoginManager(app)
login.login_view = 'login'

mail = Mail(app)

bootstrap = Bootstrap(app)

moment = Moment(app)

from flask_login import current_user, login_user, logout_user, login_required

class ModelView(ModelView):
  def is_accessible(self):
    return current_user.is_authenticated and str(current_user.username) == 'admin'

  def inaccessible_callback(self, name, **kwargs):
    # redirect to login page if user doesn't have access
    return render_template('admin_403.html'), 403

from app.models import User, Product, Release, Instance

user = User.query.filter_by(username='admin').first()
if user is None:
  print('User admin does not exist; creating user admin with password admin')
  user = User(username='admin', email='')
  user.active = True
  user.set_password('admin')
  db.session.add(user)
  db.session.commit()

class ExitView(BaseView):
  @expose('/')
  def index(self):
    sys.exit(4)

class dESPatchView(BaseView):
  @expose('/')
  def index(self):
    return redirect(url_for('index'))

admin = Admin(app)
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Product, db.session))
admin.add_view(ModelView(Release, db.session))
admin.add_view(ModelView(Instance, db.session))
admin.add_view(dESPatchView(name='dESPatch', endpoint='/index'))
admin.add_view(ExitView(name='Stop server', endpoint='exit'))

from app import routes, models, errors

if not app.debug:
  if app.config['MAIL_SERVER']:
    auth = None
    if app.config['MAIL_USERNAME'] or app.config['MAIL_PASSWORD']:
      auth = (app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
    secure = None
    if app.config['MAIL_USE_TLS']:
      secure = ()
    mail_handler = SMTPHandler(
      mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
      fromaddr='no-reply@' + app.config['MAIL_SERVER'],
      toaddrs=app.config['ADMINS'], subject='dESPatch-web Failure',
      credentials=auth, secure=secure)
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)

if not app.debug:
  if not os.path.exists('logs'):
      os.mkdir('logs')
  file_handler = RotatingFileHandler('logs/dESPatch-web.log', 
    maxBytes=10240, backupCount=10)
  file_handler.setFormatter(logging.Formatter(
      '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
  file_handler.setLevel(logging.INFO)
  app.logger.addHandler(file_handler)

  app.logger.setLevel(logging.INFO)
  app.logger.info('dESPatch-web startup')
