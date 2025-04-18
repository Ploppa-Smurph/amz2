# app.py
import os
import logging
import base64
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template
from dotenv import load_dotenv
from flask_migrate import Migrate

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-very-secure-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(app.instance_path, 'site.db')
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
from extensions import db, login_manager
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Register custom filters
@app.template_filter('b64str')
def b64str(data):
    """Converts binary data to a base64-encoded UTF-8 string."""
    if not data:
        return ''
    return base64.b64encode(data).decode('utf-8')

from amazon_utils import get_public_url
@app.template_filter('public_url')
def public_url_filter(key):
    """Returns the public URL for an S3 key."""
    return get_public_url(key)

# Register blueprints
from blueprints.reports.routes import reports_bp
from blueprints.auth.routes import auth_bp
app.register_blueprint(reports_bp, url_prefix='/reports')
app.register_blueprint(auth_bp, url_prefix='/auth')

# Base routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/future-plans')
def future_plans():
    return render_template('future_plans.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if not app.debug:
    # Ensure the logs directory exists
    if not os.path.exists('logs'):
        os.mkdir('logs')
    # Create a rotating file handler: logs file will be logs/myapp.log
    file_handler = RotatingFileHandler('logs/myapp.log', maxBytes=10240, backupCount=10)
    # Set the logging format
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('MyApp startup')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    with app.app_context():
        # db.create_all()  # For development; in production rely on migrations
        app.run(debug=True)