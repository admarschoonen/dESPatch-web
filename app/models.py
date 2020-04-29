from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login, app
from time import time
import jwt

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(64), index=True, unique=True)
  email = db.Column(db.String(120), index=True, unique=True)
  active = db.Column(db.Boolean)
  user_url = db.Column(db.String(128), index=True) # REMOVE ME
  password_hash = db.Column(db.String(128))
  products = db.relationship('Product', backref='user', lazy='dynamic')

  def set_password(self, password):
    self.password_hash = generate_password_hash(password)

  def check_password(self, password):
    return check_password_hash(self.password_hash, password)

  def __repr__(self):
    return '<User {}>'.format(self.username)  

  def get_reset_password_token(self, expires_in=600):
    return jwt.encode({'reset_password': self.id, 'exp': time() + expires_in},
      app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

  @staticmethod
  def verify_reset_password_token(token):
    try:
      id = jwt.decode(token, app.config['SECRET_KEY'],
        algorithms=['HS256'])['reset_password']
    except:
      return
    return User.query.get(id)

class Product(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(64))
  timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  latest_release_id = db.Column(db.Integer, index=True)
  product_url = db.Column(db.String(128), index=True) # REMOVE ME
  update_interval = db.Column(db.Integer, default=24 * 3600)
  key = db.Column(db.String(32))
  version = db.Column(db.String(64), index=True) # REMOVE ME
  releases = db.relationship('Release', backref='product', lazy='dynamic')
  instances = db.relationship('Instance', backref='product', lazy='dynamic')

  def __repr__(self):
    return '<Product {}, user_id: {}>'.format(self.name, self.user_id)

class Release(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  version = db.Column(db.String(64), index=True)
  timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
  filename = db.Column(db.String(120), index=True)
  release_notes = db.Column(db.String(128), index=True)
  product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
  update_interval = db.Column(db.Integer, default=24*3600)

  def __repr__(self):
    return '<Release {}, product_id: {}>'.format(self.version, self.product_id)

class Instance(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  mac = db.Column(db.String(12), index=True)
  current_version = db.Column(db.String(64), index=True)
  custom_version = db.Column(db.String(64), index=True)
  last_time_seen = db.Column(db.DateTime, index=True, default=datetime.utcnow)
  product_id = db.Column(db.Integer, db.ForeignKey('product.id'))

  def __repr__(self):
    return '<MAC {}>'.format(self.mac)

@login.user_loader
def load_user(id):
  return User.query.get(int(id))
