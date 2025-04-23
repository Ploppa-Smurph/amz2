import os
import logging
import base64
import uuid
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, session
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

# Force session cookies to be non-permanent so they expire on browser close.
app.config['SESSION_PERMANENT'] = False

# Set a unique identifier for this server run.
app.config['SERVER_RUN_ID'] = str(uuid.uuid4())

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
from blueprints.reports.routes import reports as reports_bp
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
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/myapp.log', maxBytes=10240, backupCount=10)
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

# Invalidate old sessions when the server restarts.
from flask_login import current_user, logout_user
@app.before_request
def invalidate_old_session():
    if current_user.is_authenticated:
        # Compare the session's stored run_id with the current run id.
        if session.get('server_run_id') != app.config.get('SERVER_RUN_ID'):
            logout_user()
            session.clear()

if __name__ == '__main__':
    from models import User  # Ensure the User model is imported.
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin", email="admin@example.com", role="admin")
            admin.set_password("password")
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: username='admin' password='password'")
    app.run(debug=True)