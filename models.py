from datetime import datetime
from extensions import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    reports = db.relationship('Report', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
    
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except Exception:
            return None
        return User.query.get(user_id)


# Association table for many-to-many between Report and Tag
report_tags = db.Table('report_tags',
    db.Column('report_id', db.Integer, db.ForeignKey('report.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)

    def __repr__(self):
        return f"Tag('{self.name}')"

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    # Existing image data: if an image is directly stored in the DB
    image_data = db.Column(db.LargeBinary)
    image_mimetype = db.Column(db.String(50))
    # Original posting date (in case EXIF isn’t available)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # New field: store the S3 key for the image
    s3_key = db.Column(db.String(255), nullable=True)
    # New field: store the actual image EXIF taken datetime
    exif_datetime = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Many-to-many relationship with Tag
    tags = db.relationship('Tag', secondary=report_tags, backref=db.backref('reports', lazy='dynamic'))

    def __repr__(self):
        # Use the EXIF time if available; otherwise fall back to date_posted
        taken = self.exif_datetime if self.exif_datetime else self.date_posted
        return f"Report('{self.title}', Taken on: '{taken}')"