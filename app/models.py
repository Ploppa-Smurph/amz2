from datetime import datetime
from app.extensions import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Association table for many-to-many relationship between Report and Tag
report_tags = db.Table('report_tags',
    db.Column('report_id', db.Integer, db.ForeignKey('reports.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
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
        from itsdangerous import URLSafeTimedSerializer
        from flask import current_app
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return serializer.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
        from flask import current_app
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            data = serializer.loads(token, max_age=expires_sec)
        except (SignatureExpired, BadSignature):
            return None
        return db.session.get(User, data['user_id'])

class Tag(db.Model):
    __tablename__ = 'tags'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)

    def __repr__(self):
        return f"Tag('{self.name}')"

class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=True)
    image_data = db.Column(db.LargeBinary, nullable=True)
    image_mimetype = db.Column(db.String(50), nullable=True)
    s3_key = db.Column(db.String(256), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    exif_datetime = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    threaded_notes = db.relationship('Note', backref='report', lazy=True)
    tags = db.relationship('Tag', secondary=report_tags, lazy='subquery',
                           backref=db.backref('reports', lazy=True))

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

class Note(db.Model):
    __tablename__ = 'notes'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    report_id = db.Column(db.Integer, db.ForeignKey('reports.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref='notes', lazy=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('notes.id'), nullable=True)
    replies = db.relationship('Note',
                              backref=db.backref('parent', remote_side=[id]),
                              lazy=True)

    def __repr__(self):
        snippet = (self.content[:20] + '...') if len(self.content) > 20 else self.content
        return f"Note(ID:{self.id}, {self.timestamp}, '{snippet}')"