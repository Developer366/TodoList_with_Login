#from Modules import app, LoginForm
from flask import render_template, url_for, flash, redirect
from Modules import app
from Modules.forms import LoginForm, RegistrationForm
from Modules.models import Todo, User
from flask_login import LoginManager, logout_user, login_required, current_user, login_user

'''
@app.route('/')
#@app.route('/index')
def index():
    #return "<p>yo this wak</p>"
    return render_template('index.html')

'''

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
#@login_required
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            # login_user(user)  # , remember=form.remember_me.data
            flash('Invalid Username or Password')
            return redirect(url_for('main.login'))
    return render_template('login3.html', title='Sign In', form=form)

'''
@app.route('/')
#@app.route('/index')
def index():
    #return "<p>yo this wak</p>"
    return render_template('register.html')
    
    @app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    return render_template('login.html', form=form)

'''