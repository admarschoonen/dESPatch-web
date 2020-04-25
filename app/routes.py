from flask import render_template, flash, redirect, url_for, request, send_from_directory
from app import app, db
from app.forms import LoginForm, RegistrationForm, EditProfileForm, EditProductForm, EditReleaseForm, EditInstanceForm, ResetPasswordForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Product, Release, Instance
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from app.forms import ResetPasswordRequestForm
from app.email import send_password_reset_email
from datetime import datetime
import random, string
from sqlalchemy import desc
import os
import json
import base64

@app.route('/')
@app.route('/index')
@login_required
def index():
  user = User.query.filter_by(username=current_user.username).first()
  products = Product.query.filter_by(user_id=current_user.id)
  return render_template('index.html', title='dESPatch-web', products=products, add_product_link=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
  if current_user.is_authenticated:
    return redirect(url_for('index'))
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    if user is None or not user.check_password(form.password.data):
      flash('Invalid username or password', 'warning')
      return redirect(url_for('login'))
    if user.active == False:
      flash('Account is inactive; check your e-mail for the actiavtion link or reset your password', 'warning')
      return redirect(url_for('login'))
    login_user(user, remember=form.remember_me.data)
    next_page = request.args.get('next')
    if not next_page or url_parse(next_page).netloc != '':
      next_page = url_for('index')
    return redirect(next_page)
  return render_template('login.html', title='Sign in', form=form)

@app.route('/logout')
def logout():
  logout_user()
  return redirect(url_for('index'))

# from https://stackoverflow.com/questions/2030053/random-strings-in-python
def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

@app.route('/register', methods=['GET', 'POST'])
def register():
  if current_user.is_authenticated:
    return redirect(url_for('index'))
  form = RegistrationForm()
  if form.validate_on_submit():
    user = User(username=form.username.data, email=form.email.data)
    user.active = False;
    # Set password to something random
    user.set_password(randomword(16))
    db.session.add(user)
    db.session.commit()
    send_password_reset_email(user)
    flash('Check your email for instructions to reset your password', 'info')
    return redirect(url_for('index'))
  return render_template('register.html', title='Register', form=form)

@app.route('/user/<username>')
@login_required
def user(username):
  if current_user.is_authenticated == False:
    return redirect(url_for('index'))
  user = User.query.filter_by(username=username).first_or_404()
  products = Product.query.filter_by(user_id=current_user.id)
  return render_template('user.html', user=user, products=products, add_product_link=True)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
  form = EditProfileForm(current_user.username)
  if form.validate_on_submit():
    current_user.username = form.username.data
    db.session.commit()
    flash('Your changes have been saved.', 'success')
    return redirect(url_for('edit_profile'))
  elif request.method == 'GET':
    form.username.data = current_user.username
  return render_template('edit_profile.html', title='Edit profile', form=form)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
  form = EditProductForm()
  if form.validate_on_submit():
    product = Product(name=form.name.data)
    product.key = randomword(32)
    product.user_id = current_user.id
    db.session.add(product)
    db.session.commit()
    flash('Your changes have been saved.', 'success')
    return redirect(url_for('index'))
  return render_template('add_product.html', title='Add product', form=form)

@app.route('/product/<product_id>')
@login_required
def product(product_id):
  product = Product.query.filter_by(id=product_id).first()
  if product == None:
    return render_template('404.html', user=user), 404

  if product.user_id == current_user.id:
    releases = Release.query.filter_by(product_id=product.id)
    latest_release = releases.order_by(desc(Release.timestamp)).first()
    if latest_release != None:
      product.version = latest_release.version

    links = []
    for release in releases:
      l = os.path.join('/files', str(product.id), str(release.id), release.filename)
      links.append(l)

    hostname = app.config['HOSTNAME']
    return render_template('product.html', hostname=hostname, links=links, user=user, product=product, releases=releases, add_product_link=False)
  else:
    return render_template('403.html', user=user), 403

@app.route('/edit_product/<product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
  form = EditProductForm()
  product = Product.query.filter_by(id=product_id).first()

  if product.user_id != current_user.id:
    return render_template('403.html', user=user), 403

  if form.validate_on_submit():
    product.name = form.name.data
    db.session.commit()
    flash('Your changes have been saved.', 'success')
    return redirect(url_for('index'))
  elif request.method == 'GET':
    form.name.data = product.name
  return render_template('edit_product.html', title='Edit product', 
    product_id=product_id, form=form)

def create_dir(D):
  d = ''
  for x in D.split('/'):
    d = os.path.join(d, x)
    if os.path.exists(d) == False:
      os.mkdir(d)
    if os.path.isdir(d) == False:
      print('Error: directory ' + d + ' is not a directory')
      return -1

  return 0

def create_json(product_id, release):
  update_interval = release.update_interval
  if update_interval == None:
    update_interval = 10

  j = {}
  j['version'] = release.version
  j['filename'] = os.path.join(str(release.id), release.filename)
  j['updateInterval'] = release.update_interval

  jsonfile = os.path.join(app.config['UPLOAD_FOLDER'], 
    str(product_id), 'despatch.json')

  ret = 0
  try:
    with open(jsonfile, 'w') as outfile:
      json.dump(j, outfile)
  except:
    ret = -1

  return ret

@app.route('/add_release', methods=['GET', 'POST'])
@login_required
def add_release():
  form = EditReleaseForm('add', '')
  product_id = request.args.get('product_id')
  product = Product.query.filter_by(id=product_id).first()
  form.update_interval.data = product.update_interval
  
  if form.update_interval.data == None:
    form.update_interval.data = 24 * 3600

  if product.user_id != current_user.id:
    return render_template('403.html', user=user), 403

  if form.validate_on_submit():
    release = Release(version=form.version.data)
    release.timestamp = datetime.utcnow()
    release.filename = secure_filename(form.file.data.filename)
    release.release_notes = form.release_notes.data
    release.product_id = product.id
    release.update_interval = form.update_interval.data
    product.version = release.version
    db.session.add(release)
    db.session.commit()

    d = os.path.join(app.config['UPLOAD_FOLDER'], str(product_id), str(release.id))
    if create_dir(d) < 0:
      print('Internal error while creating directory: ' + d)
      return render_template('500.html', user=user), 500

    f = os.path.join(d, release.filename)
    form.file.data.save(f)
  
    if create_json(product.id, release) == 0:
      flash('Your changes have been saved.', 'success')
    else:
      flash('Oops. Something went wrong', 'error')
    return redirect(url_for('product', product_id=product.id))
  return render_template('add_release.html', title='Add release', 
    product_id=product_id, form=form)

@app.route('/edit_release', methods=['GET', 'POST'])
@login_required
def edit_release():
  product_id = request.args.get('product_id')
  product = Product.query.filter_by(id=product_id).first()

  if product.user_id != current_user.id:
    return render_template('403.html', user=user), 403

  release_id = request.args.get('release_id')
  release = Release.query.filter_by(id=release_id).first()

  if product.user_id != current_user.id:
    return render_template('403.html', user=user), 403

  form = EditReleaseForm('edit', release.filename)

  if form.validate_on_submit():
    release.version = form.version.data
    if form.file.data:
      release.filename = secure_filename(form.file.data.filename)

      d = os.path.join(app.config['UPLOAD_FOLDER'], str(product_id), str(release_id))
      if create_dir(d) < 0:
        print('Internal error while creating directory: ' + d)
        return render_template('500.html', user=user), 500

      f = os.path.join(d, release.filename)
      form.file.data.save(f)

    release.release_notes = form.release_notes.data
    release.timestamp = datetime.utcnow()
    product.version = release.version
    release.update_interval = form.update_interval.data
    db.session.commit()

    if create_json(product.id, release) == 0:
      flash('Your changes have been saved.', 'success')
    else:
      flash('Oops. Something went wrong', 'error')
    return redirect(url_for('product', product_id=product.id))
  elif request.method == 'GET':
    form.version.data = release.version
    #form.file.data = release.filename
    form.release_notes.data = release.release_notes
    form.current_filename = release.filename
    form.update_interval.data = release.update_interval
    flash('Warning! Editing of a release is not recommended. Only do this if you''re sure what you are doing!', 'warning')
  return render_template('edit_release.html', title='Edit release', 
    release_id=release_id, product_id=product_id, form=form)

@app.route('/edit_instance', methods=['GET', 'POST'])
@login_required
def edit_instance():
  form = EditInstanceForm()
  if form.validate_on_submit():
    current_user.mac = form.mac.data
    current_user.custom_version = form.custom_version.data
    db.session.commit()
    flash('Your changes have been saved.', 'success')
    return redirect(url_for('edit_instance'))
  elif request.method == 'GET':
    form.mac.data = current_user.mac
    form.custom_version.data = current_user.custom_version
  return render_template('edit_instance.html', title='Edit instance', form=form)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
  if current_user.is_authenticated:
    return redirect(url_for('index'))
  form = ResetPasswordRequestForm()
  if form.validate_on_submit():
    user = User.query.filter_by(email=form.email.data).first()
    if user:
      send_password_reset_email(user)
      flash('Check your email for instructions to reset your password', 'info')
      return redirect(url_for('login'))
    else:
      flash('E-mail address not found', 'danger')
      return redirect(url_for('reset_password_request'))
  return render_template('reset_password_request.html',
      title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
  if current_user.is_authenticated:
    return redirect(url_for('index'))
  user = User.verify_reset_password_token(token)
  if not user:
    return redirect(url_for('index'))
  form = ResetPasswordForm()
  if form.validate_on_submit():
    user.set_password(form.password.data)
    user.active = True;
    db.session.commit()
    flash('Your password has been reset.', 'info')
    return redirect(url_for('login'))
  return render_template('reset_password.html', form=form)

@app.route(os.path.join('/files/', '<path:filename>'))
def download_file(filename):
  auth_invalid = True

  tmp = filename.split('/')
  product_id = int(tmp[0])
  product = Product.query.filter_by(id=product_id).first()

  if product == None:
      return render_template('404.html', user=user), 404

  if current_user.is_authenticated and product.user_id == current_user.id:
    auth_invalid = False

  hdr_key = request.headers.get('Authorization')
  if hdr_key != None and hdr_key.startswith('Basic '):
    # Strip 'Basic ' from hdr_key and decode Base64 data
    tmp = hdr_key[6:]
    user_key = str(base64.b64decode(tmp))
    
    # Strip 1st and 2nd characters (b') and last char (')
    user_key = user_key[2:-1]

    if user_key.startswith('apikey:'):
      # Strip 'apikey:' and compare keys
      key = user_key[7:]
      if key == product.key:
        auth_invalid = False
  
  if auth_invalid:
    return render_template('403.html', user=user), 403

  upload_folder = app.config['UPLOAD_FOLDER']

  if upload_folder[0] != '/':
    d = os.path.realpath(__file__)
    tmp = d.split('/')
    upload_folder = os.path.join('/'.join(tmp[0:len(tmp) - 2]), upload_folder)

  print("sending file " + os.path.join(upload_folder, filename))
  return send_from_directory(upload_folder, filename)

