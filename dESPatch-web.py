from app import app, db
from app.models import User, Product, Release, Instance

@app.shell_context_processor
def make_shell_context():
  return {'db': db, 'User': User, 'Product': Product, 'Release': Release, 'Instance': Instance}
