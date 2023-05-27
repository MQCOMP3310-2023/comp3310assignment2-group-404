from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy import text
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password and compare it with the stored password
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        current_app.logger.warning("User login failed")
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.showRestaurants'))

@auth.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        role = request.form.get('role')  

        # Validate form inputs

        # Check if the user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('An account with this email already exists.')
            return redirect(url_for('auth.signup'))
        
        password_hash = generate_password_hash(password)

        # Create a new user
        new_user = User(email=email, password=password_hash, name=name, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. Please log in.')
        return redirect(url_for('auth.login'))
    
    return render_template('signup.html')

#Change password
@auth.route('/profile/passwordChange', methods = ['GET', 'POST'])
@login_required
def changePassword():
    if request.method == 'POST':
        
        user = db.session.query(User).filter_by(id = current_user.id).one()

        #get form data
        originalpassword = request.form.get('originalpassword')
        newpassword = request.form.get('newpassword')
        confirmpassword = request.form.get('confirmpassword')

        #validate form inputs

        #check password is correct
        if not check_password_hash(current_user.password, originalpassword):
            flash('Please check your login details and try again.')
            current_app.logger.warning("User password change failed")
            return redirect(url_for('auth.changePassword')) #if the password is wrong, reload the page
        
        #TODO check comfirmation and new password are same

        #generate new password hash
        password_hash = generate_password_hash(newpassword)

        #update password in database
        user.password = password_hash
        db.session.add(user)
        db.session.commit() 

        flash('Password updated successfully')
        return redirect(url_for('main.profile'))
    
    return render_template('passwordChange.html', name=current_user.name)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.showRestaurants'))
