# File: app/utils/db_helpers.py
from flask import current_app
from extensions import db

def commit_or_rollback():
    """
    Attempts to commit the current database session.
    If an error occurs, roll back the session and log the error.
    Returns True if commit was successful, False otherwise.
    """
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Database commit error: {e}")
        return False