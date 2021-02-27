#from Modules import app, LoginForm
from flask import render_template, url_for, flash, redirect
from Modules import app
from Modules.forms import LoginForm, RegistrationForm
from Modules.models import Todo, User


#routes
@app.route("/")
def index():
    return 'yo this wak'
    #return render_template("login.html")

@app.route('/login')
def login():
    form = LoginForm()
    return render_template('login.html', form=form)