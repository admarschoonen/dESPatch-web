from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
#from wtforms.validators import ValidationError, InputRequired, Email, EqualTo, DataRequired, URL, Length, MacAddress, FileRequired
from wtforms.validators import ValidationError, InputRequired, Email, EqualTo, DataRequired, URL, Length, MacAddress
from app.models import User

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

class EditProfileForm(FlaskForm):
  username = StringField('Username', validators=[InputRequired(), Length(min=1, max=64)])
  submit = SubmitField('OK')

  def __init__(self, original_username, *args, **kwargs):
    super(EditProfileForm, self).__init__(*args, **kwargs)
    self.original_username = original_username

  def validate_username(self, username):
    if username.data != self.original_username:
      user = User.query.filter_by(username=self.username.data).first()
      if user is not None:
        raise ValidationError('Please use a different username.')

class EditProductForm(FlaskForm):
  name = StringField('Name', validators=[InputRequired(), Length(min=1, max=64)])
  submit = SubmitField('OK')

class EditReleaseForm(FlaskForm):
  version = StringField('Version', validators=[InputRequired(), Length(min=1, max=64)])
  release_notes = StringField('Release notes URL', validators=[URL()])
  #filename = FileField(validators=[FileRequired()])
  file = FileField()
  submit = SubmitField('OK')

class EditInstanceForm(FlaskForm):
  mac = StringField('MAC address', validators=MacAddress())
  custom_version = StringField('Custom version', validators=[InputRequired(), Length(min=1, max=64)])
  submit = SubmitField('OK')

class ResetPasswordRequestForm(FlaskForm):
  email = StringField('Email', validators=[InputRequired(), Email(), Length(min=1, max=120)])
  submit = SubmitField('Request password reset')

class ResetPasswordForm(FlaskForm):
  password = PasswordField('Password', validators=[InputRequired()])
  password2 = PasswordField(
    'Repeat Password', validators=[InputRequired(), EqualTo('password')])
  submit = SubmitField('Register')
