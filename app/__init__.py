import os
import logging
import base64
import uuid
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, session
from dotenv import load_dotenv
from flask_migrate import Migrate

# Load environment variables from .env
load_dotenv()

# Import the shared extensions at the module level.
from app.extensions import db, login_manager

def create_app(test_config=None):
    # Determine the project root directory.
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    # Create the Flask application.
    app = Flask(
        __name__,
        template_folder=os.path.join(basedir, 'templates'),
        static_folder=os.path.join(basedir, 'static'),
        instance_path=os.path.join(basedir, 'instance'),
        instance_relative_config=True
    )

    # Load default configuration.
    # When deploying to Railway, set the environment variable DATABASE_URL to:
    #     ${{ Postgres.DATABASE_URL }}
    # This ensures that your app connects to Railway's PostgreSQL instance.
    app.config.from_mapping(
        SECRET_KEY=os.getenv('SECRET_KEY', 'your-very-secure-secret-key'),
        SQLALCHEMY_DATABASE_URI=os.getenv(
            'DATABASE_URL',  # Railway will provide a PostgreSQL URL here.
            'sqlite:///' + os.path.join(app.instance_path, 'site.db')
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_PERMANENT=False,
        SERVER_RUN_ID=str(uuid.uuid4()),
        AUTO_CREATE_DB=False,  # Set to True only if you want to auto-create tables without dropping.
        AUTO_DROP_DB=False,    # For development only. In production, set this to False.
    )

    # Override configuration if test_config is provided.
    if test_config is not None:
        app.config.update(test_config)

    # Ensure the instance folder exists.
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Initialize extensions.
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    # Initialize Flask-Migrate.
    Migrate(app, db)

    # Register custom Jinja filters.
    @app.template_filter('b64str')
    def b64str_filter(data):
        if not data:
            return ''
        return base64.b64encode(data).decode('utf-8')
    app.jinja_env.filters['b64str'] = b64str_filter

    from app.utils.amazon_utils import get_public_url
    @app.template_filter('public_url')
    def public_url_filter(key):
        return get_public_url(key)
    app.jinja_env.filters['public_url'] = public_url_filter

    # Register blueprints.
    from app.blueprints.reports import reports_bp
    from app.blueprints.auth import auth_bp
    app.register_blueprint(reports_bp, url_prefix='/reports')
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Define Base Routes.
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
        return render_template('about.html')  # Using about.html for contact.

    # Configure logging (only if not in debug mode).
    if not app.debug:
        logs_dir = os.path.join(basedir, 'logs')
        if not os.path.exists(logs_dir):
            os.mkdir(logs_dir)
        file_handler = RotatingFileHandler(
            os.path.join(logs_dir, 'myapp.log'),
            maxBytes=10240,
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('MyApp startup')

    # Custom 404 error handler.
    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('404.html'), 404

    # Invalidate old sessions when the server restarts.
    from flask_login import current_user, logout_user
    @app.before_request
    def invalidate_old_session():
        if current_user.is_authenticated:
            if session.get('server_run_id') != app.config.get('SERVER_RUN_ID'):
                logout_user()
                session.clear()

    # Optional: Drop (if configured) and/or create tables.
    with app.app_context():
        if app.config.get("AUTO_DROP_DB", False):
            db.drop_all()
            app.logger.info("Dropped all tables in the database.")
            db.create_all()
            app.logger.info("Created all tables in the database after dropping them.")
        elif app.config.get("AUTO_CREATE_DB", False):
            db.create_all()
            app.logger.info("Created all tables in the database.")

    # Create default admin if not already present.
    with app.app_context():
        try:
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            if inspector.has_table("users"):
                from app.models import User
                admin = User.query.filter_by(username="admin").first()
                if admin:
                    if admin.role != "admin":
                        admin.role = "admin"
                        admin.set_password(os.getenv("DEFAULT_ADMIN_PASSWORD", "password"))
                        db.session.commit()
                        app.logger.info("Existing user 'admin' updated to admin permissions.")
                    else:
                        app.logger.info("Admin user 'admin' already exists with proper permissions.")
                else:
                    admin = User(username="admin", email="admin@example.com", role="admin")
                    admin.set_password(os.getenv("DEFAULT_ADMIN_PASSWORD", "password"))
                    db.session.add(admin)
                    db.session.commit()
                    app.logger.info(
                        "Default admin user created: username='admin' with password='%s'",
                        os.getenv("DEFAULT_ADMIN_PASSWORD", "password")
                    )
            else:
                app.logger.warning("Skipping default admin creation: 'users' table does not exist.")
        except Exception as e:
            app.logger.error("Error during default admin creation: %s", e)

    return app

__all__ = ['create_app', 'db']