import os
import sys
# Add the project root to the Python path so that "app" can be imported.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from app import create_app, db
from app.models import User, Report, Tag, Note

# -----------------------------------------------------------------------------
# Pytest fixtures: create the test application, client, and CLI runner.
# -----------------------------------------------------------------------------

@pytest.fixture
def app():
    # Define a configuration dictionary for testing.
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False
    }
    # Create the Flask application using the factory, passing in test_config.
    app = create_app(test_config)
    with app.app_context():
        # Create all tables in the in-memory database.
        db.create_all()

        # Optionally, populate the database with sample data.
        sample_user = User(username="sample", email="sample@example.com", role="user")
        sample_user.set_password("testpass")
        db.session.add(sample_user)
        db.session.commit()

        yield app

        # Teardown: remove database session and drop all tables.
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


# -----------------------------------------------------------------------------
# Endpoint and route tests.
# -----------------------------------------------------------------------------

def test_home_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    # Optionally, check for expected text in your home template.
    assert b"Welcome" in response.data or b"Home" in response.data


def test_about_endpoint(client):
    response = client.get("/about")
    assert response.status_code == 200


def test_future_plans_endpoint(client):
    response = client.get("/future-plans")
    assert response.status_code == 200


def test_contact_endpoint(client):
    response = client.get("/contact")
    assert response.status_code == 200


def test_profile_requires_login(client):
    # Accessing /auth/profile without logging in should redirect to the login page.
    response = client.get("/auth/profile", follow_redirects=True)
    assert b"Login" in response.data


# -----------------------------------------------------------------------------
# Form validation tests.
# -----------------------------------------------------------------------------

def test_registration_form_validation(app):
    from app.forms import RegistrationForm
    with app.test_request_context("/auth/register", method="POST", data={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirm_password": "password123"
    }):
        form = RegistrationForm()
        assert form.validate(), "RegistrationForm should be valid with correct data."


def test_login_form_validation(app):
    from app.forms import LoginForm
    with app.test_request_context("/auth/login", method="POST", data={
        "username": "testuser",
        "password": "password123"
    }):
        form = LoginForm()
        assert form.validate(), "LoginForm should validate when correct data is provided."


def test_report_form_validation(app):
    from app.forms import ReportForm
    with app.test_request_context("/reports/post", method="POST", data={
        "title": "Test Report",
        "notes": "This is a test report"
    }):
        form = ReportForm()
        assert form.validate(), "ReportForm should validate with proper data."


# -----------------------------------------------------------------------------
# Database and model tests.
# -----------------------------------------------------------------------------

def test_password_hashing(app):
    with app.app_context():
        user = User(username="hashuser", email="hash@example.com", role="user")
        user.set_password("secret")
        assert user.password_hash != "secret"
        assert user.check_password("secret")
        assert not user.check_password("wrong")


def test_reset_token(app):
    with app.app_context():
        user = User(username="resetuser", email="reset@example.com", role="user")
        user.set_password("password")
        db.session.add(user)
        db.session.commit()
        token = user.get_reset_token()
        retrieved_user = User.verify_reset_token(token)
        assert retrieved_user is not None
        assert retrieved_user.username == "resetuser"


# -----------------------------------------------------------------------------
# Functional endpoint tests (registration, login, logout, and protected pages)
# -----------------------------------------------------------------------------

def test_duplicate_user_registration(app, client):
    # Create an initial user.
    with app.app_context():
        user = User(username="duplicate", email="duplicate@example.com", role="user")
        user.set_password("password")
        db.session.add(user)
        db.session.commit()

    # Attempt registration with the same username.
    response = client.post("/auth/register", data={
        "username": "duplicate",
        "email": "new@example.com",
        "password": "password",
        "confirm_password": "password"
    }, follow_redirects=True)
    # Check that an error message is flashed.
    assert b"That username is taken" in response.data or b"taken" in response.data


def test_user_login_logout(app, client):
    with app.app_context():
        user = User(username="loginuser", email="loginuser@example.com", role="user")
        user.set_password("password")
        db.session.add(user)
        db.session.commit()

    # Login the user.
    login_response = client.post("/auth/login", data={
        "username": "loginuser",
        "password": "password"
    }, follow_redirects=True)
    # Check that the profile page (or similar) is displayed.
    assert b"Profile" in login_response.data or b"Back to Profile" in login_response.data

    # Logout the user.
    logout_response = client.get("/auth/logout", follow_redirects=True)
    # After logout, the login link should be visible.
    assert b"Login" in logout_response.data


def test_reports_daily_reports_requires_login(client):
    # Accessing the reports daily page without logging in should redirect to login.
    response = client.get("/reports/daily_reports", follow_redirects=True)
    assert b"Login" in response.data
