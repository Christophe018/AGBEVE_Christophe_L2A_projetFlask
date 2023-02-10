from flask import Blueprint, render_template, request, flash, redirect, url_for 
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db 
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)

@auth.route('/login', methods =['GET','POST'])

def login():
    login_user
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email1 = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email1).first()
        if user:
            if check_password_hash(user.password, password):
                #flash('Connexion Réussie!', category='success')
                login_user(user)
                return redirect(url_for('views.home'))
            else:
                flash('Mot de passe incorrect', category='error')
        else:
            flash('Please enter correct email !', category='error')
    return render_template('login.html', user=current_user)

@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/register', methods = ['GET','POST'])
def register():
    if request.method == 'POST' and 'nom' in request.form and 'prenom' in request.form and 'email' in request.form :
        userName = request.form.get('nom')
        userPname = request.form.get('prenom')
        password = request.form.get('password')
        email1 = request.form.get('email')
        account = User.query.filter_by(email=email1).first()
        if account:
            flash('Account already exists !', category='error')
        elif not userName or not userPname or not password or not email1: 
            flash('Veuillez remplir tous les champs', category='error') 
        else:
            new_user = User(email=email1, nom=userName, prenom=userPname, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Compte créé avec succès', category='success')
            return redirect(url_for('auth.login'))
    elif request.method == 'POST':
        flash('Please fill out the form', category='error')
    return render_template('register.html', user = current_user)