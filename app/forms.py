from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, IntegerField, SelectField
#from wtforms.validators import ValidationError, InputRequired, Email, EqualTo, DataRequired, URL, Length, MacAddress, FileRequired
from wtforms.validators import ValidationError, InputRequired, Email, EqualTo, DataRequired, URL, Length, MacAddress, StopValidation, NumberRange, NoneOf
from app.models import User

class MyInputRequired(InputRequired):
  field_flags = ()

class LoginForm(FlaskForm):
  username = StringField('Username', validators=[InputRequired()])
  password = PasswordField('Password', validators=[InputRequired()])
  remember_me = BooleanField('Remember me')
  submit = SubmitField('Sign in')

class RegistrationForm(FlaskForm):
  username = StringField('Username', validators=[InputRequired(), Length(min=1, max=64)])
  email = StringField('Email', validators=[InputRequired(), Email(), Length(min=1, max=120)])
  submit = SubmitField('Register')

  def validate_username(self, username):
    user = User.query.filter_by(username=username.data).first()
    if user is not None:
      raise ValidationError('Please use a different username.')

  def validate_email(self, email):
    user = User.query.filter_by(email=email.data).first()
    if user is not None:
      raise ValidationError('Please use a different email address.')

class EditAdminProfileForm(FlaskForm):
  email = StringField('Email', validators=[InputRequired(), Email(), Length(min=1, max=120)])
  password = PasswordField('Password')
  password2 = PasswordField(
    'Repeat Password', validators=[EqualTo('password')])
  submit = SubmitField('OK')
  cancel = SubmitField('Cancel')

  def __init__(self, original_email, *args, **kwargs):
    super(EditAdminProfileForm, self).__init__(*args, **kwargs)
    self.original_email = original_email
    self.password.description = 'Leave the password fields empty if you don''t want to change your password'

  def validate_email(self, email):
    if email.data != self.original_email:
      user = User.query.filter_by(email=self.email.data).first()
      if user is not None:
        raise ValidationError('Please use a different email.')

class EditProfileForm(FlaskForm):
  username = StringField('Username', validators=[InputRequired(), Length(min=1, max=64), NoneOf(['admin'])])
  email = StringField('Email', validators=[InputRequired(), Email(), Length(min=1, max=120)])
  password = PasswordField('Password')
  password2 = PasswordField(
    'Repeat Password', validators=[EqualTo('password')])
  submit = SubmitField('OK')
  cancel = SubmitField('Cancel')

  def __init__(self, original_username, original_email, *args, **kwargs):
    super(EditProfileForm, self).__init__(*args, **kwargs)
    self.original_username = original_username
    self.original_email = original_email
    self.password.description = 'Leave the password fields empty if you don''t want to change your password'

  def validate_username(self, username):
    if username.data != self.original_username:
      user = User.query.filter_by(username=self.username.data).first()
      if user is not None:
        raise ValidationError('Please use a different username.')

  def validate_email(self, email):
    if email.data != self.original_email:
      user = User.query.filter_by(email=self.email.data).first()
      if user is not None:
        raise ValidationError('Please use a different email.')

class EditProductForm(FlaskForm):
  name = StringField('Name', validators=[MyInputRequired(), Length(min=1, max=64)])
  submit = SubmitField('OK')
  cancel = SubmitField('Cancel')

class EditReleaseForm(FlaskForm):
  version = StringField('Version', validators=[MyInputRequired(), Length(min=1, max=64)])
  release_notes = StringField('Release notes')
  update_interval = IntegerField('Update interval (seconds)', validators=[MyInputRequired(), NumberRange(min=10, max=None, message='Minimum value is 10')])
  file = FileField()
  is_latest_release = BooleanField('Make this release the latest version')
  submit = SubmitField('OK')
  cancel = SubmitField('Cancel')

  def __init__(self, mode, filename, versions, *args, **kwargs):
    super(EditReleaseForm, self).__init__(*args, **kwargs)
    self.mode = mode
    self.file.description = 'Export a compiled binary from your sketch in Arduino by selecting "Sketch" -> "Export compiled Binary", then upoad it here.'
    if self.mode == 'edit':
      self.file.description = self.file.description + '\nCurrently stored file: ' + filename
    self.versions = versions

  def validate_file(self, file):
    if self.mode == 'add':
      if file.data == None:
        raise ValidationError('Please upload a binary for ESP32.')
    if self.mode == 'edit':
      if file.data == None:
        raise StopValidation()

  def validate_version(self, version):
    for v in self.versions:
      if v == version.data:
        raise ValidationError('Version already exists')

class EditInstanceForm(FlaskForm):
  description = StringField('Description', validators=[Length(max=128)])
  custom_version = SelectField('Custom version')
  submit = SubmitField('OK')
  cancel = SubmitField('Cancel')

class ResetPasswordRequestForm(FlaskForm):
  email = StringField('Email', validators=[InputRequired(), Email(), Length(min=1, max=120)])
  submit = SubmitField('Request password reset')

class ResetPasswordForm(FlaskForm):
  password = PasswordField('Password', validators=[InputRequired()])
  password2 = PasswordField(
    'Repeat Password', validators=[InputRequired(), EqualTo('password')])
  submit = SubmitField('Register')
