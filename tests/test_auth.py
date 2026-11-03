import pytest
from app import create_app
from models.database import db, User
from config import Config

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        # Seed test admin
        admin = User(
            username='admin_test',
            email='admin@test.local',
            role='admin',
            department='SOC'
        )
        admin.set_password('AdminPass123!')
        db.session.add(admin)

        # Seed standard user
        standard = User(
            username='user_test',
            email='user@test.local',
            role='user',
            department='HR'
        )
        standard.set_password('UserPass123!')
        db.session.add(standard)
        db.session.commit()

        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_password_hashing(app):
    with app.app_context():
        u = User.query.filter_by(username='admin_test').first()
        assert u.check_password('AdminPass123!') is True
        assert u.check_password('WrongPassword') is False
        assert not u.password_hash.startswith('AdminPass123!')  # must be hashed

def test_role_properties(app):
    with app.app_context():
        admin = User.query.filter_by(username='admin_test').first()
        user = User.query.filter_by(username='user_test').first()
        assert admin.is_admin is True
        assert admin.is_analyst is True
        assert user.is_admin is False
        assert user.is_analyst is False

def test_login_success(client):
    res = client.post('/login', data={
        'username': 'admin_test',
        'password': 'AdminPass123!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'Security session initialized' in res.data or b'Security Operations Center' in res.data

def test_login_failure(client):
    res = client.post('/login', data={
        'username': 'admin_test',
        'password': 'BadPassword!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'Invalid credentials' in res.data

def test_unauthorized_access_redirect(client):
    # Access protected dashboard without logging in
    res = client.get('/', follow_redirects=False)
    assert res.status_code == 302
    assert '/login' in res.headers['Location']

def test_admin_route_forbidden_for_standard_user(client):
    # Log in as standard user
    client.post('/login', data={
        'username': 'user_test',
        'password': 'UserPass123!'
    })
    # Try accessing admin-only user management
    res = client.get('/users')
    assert res.status_code == 403
