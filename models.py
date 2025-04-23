from datetime import datetime
from extensions import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user', server_default='user')
    must_change_password = db.Column(db.Boolean, default=False, server_default='0')
    reports = db.relationship('Report', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', role='{self.role}')"

    def get_reset_token(self, expires_sec=1800):
        from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
        from flask import current_app
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
        from flask import current_app
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)


# Association table for many-to-many relationship between Report and Tag
report_tags = db.Table('report_tags',
    db.Column('report_id', db.Integer, db.ForeignKey('reports.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)

class Tag(db.Model):
    __tablename__ = 'tags'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)

    def __repr__(self):
        return f"Tag('{self.name}')"

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=True)
    
    # Image information: stored as binary or via S3 reference.
    image_data = db.Column(db.LargeBinary, nullable=True)
    image_mimetype = db.Column(db.String(50), nullable=True)
    s3_key = db.Column(db.String(255), nullable=True)
    
    # Field for notes associated with the report.
    notes = db.Column(db.Text, nullable=True)
    
    # Timestamps and optional EXIF information.
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    exif_datetime = db.Column(db.DateTime, nullable=True)
    
    # Foreign key for the author.
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __init__(self, title=None, image_data=None, image_mimetype=None, s3_key=None, notes=None, exif_datetime=None, author=None):
        self.title = title
        self.image_data = image_data
        self.image_mimetype = image_mimetype
        self.s3_key = s3_key
        self.notes = notes
        self.exif_datetime = exif_datetime
        self.author = author

    def __repr__(self):
        taken = self.exif_datetime if self.exif_datetime else self.date_posted
        return f"Report('{self.title}', Taken on: '{taken}')"