from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import Restaurant, MenuItem, Users
from sqlalchemy import asc
from sqlalchemy.orm.exc import NoResultFound
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            userToAuth = db.session.query(Users).filter_by(email=email, password=password).one()
            return render_template('restaurants.html')
        except NoResultFound:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')