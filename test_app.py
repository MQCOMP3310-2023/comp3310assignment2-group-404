import unittest
from flask import current_app, escape
from project import create_app, db
from project.models import User
from initialise_db import populate_db
from werkzeug.security import check_password_hash

class TestApp(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "SQLALCHEMY_DATABASE_URI": 'sqlite://'
            })
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.appctx = self.app.app_context()
        self.appctx.push()
        db.create_all()
        populate_db()
        self.client = self.app.test_client()

    def tearDown(self):
        db.drop_all()
        self.appctx.pop()
        self.app = None
        self.appctx = None
        self.client = None
    
    def test_app(self):
        assert self.app is not None
        assert current_app == self.app

    def test_delete_as_user(self):
        response = self.client.get('/restaurant/8/delete/', follow_redirects = True)
        assert response.status_code == 200
        assert response.request.path == '/login'

    def test_edit_as_user(self):
        response = self.client.get('/restaurant/8/edit/', follow_redirects = True)
        assert response.status_code == 200
        assert response.request.path == '/login'

    def test_hashed_passwords(self):
        response = self.client.post('/signup', data = {
            'email' : 'test@test.com',
            'password' : '1234',
            'name' : 'test',
            'role' : 'administrator'
        }, follow_redirects = True)
        assert response.status_code == 200
        assert response.request.path == '/login'

        user = User.query.filter_by(email='test@test.com').first()
        assert user is not None
        assert check_password_hash(user.password, '1234')

    def test_search(self):
        # Good Search
        response = self.client.post('/', data = {
            'search_query' : 'Panda Garden'
        })
        assert response.status_code == 200
        print(response)

        response_text = response.get_data(as_text=True)
        self.assertIn('Panda Garden', response_text)

    def test_xss_signup(self):
        response = self.client.post('/signup', data = {
            'email' : 'user@test.com',
            'password' : '1234',
            'name' : '<script>alert("XSS");</script>',
            'role' : 'administrator'
        }, follow_redirects = True)
        assert response.status_code == 200
        assert response.request.path == '/login'

        response = self.client.post('/login', data = {
            'email' : 'user@test.com',
            'password' : '1234'
        }, follow_redirects = True)
        assert response.status_code == 200

        response = self.client.get('/profile')

        response_text = response.get_data(as_text = True)
        assert escape('<script>alert("XSS");</script>') in response_text


