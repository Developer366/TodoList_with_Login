from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from werkzeug.utils import redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import *
from wtforms.validators import DataRequired, InputRequired, Email, Length, ValidationError, EqualTo, email_validator
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#Login Manager Code
login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#routes-----------------------------------------------------------------------------------------------------------
##login route
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        #now = datetime.datetime.now()
        return redirect(url_for('task'))
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        login_user(user)
        
        if user is None or not user.check_password(form.password.data):
            flash('Invalid Username or Password')
            return redirect(url_for('login'))
    return render_template('login.html', title='Login In ', form=form)

@app.route('/register', methods=['GET', "POST"])
def register():
    form = RegistrationForm()
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user! Please Login In')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register Account', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/task', methods=['GET', 'POST'])
@login_required
def task():

    if request.method == "POST":
        new_task = request.form['task']
        now = datetime.now()
        add_task = Task(task=new_task, datacreated=now)

        try:

            return redirect('/task')
        except:
            flash('There was an error adding your Task!')

    else:
        added_tasks = db.session.query(Task).all()
        return render_template('Task.html', added_tasks=added_tasks, title='List of Tasks')

@app.route('/add', methods=['POST'])
def add():
    new_task = request.form['task']
    now = datetime.now()
    add_task = Task(task=new_task, datacreated=now)
    db.session.add(add_task)
    db.session.commit()
    return redirect(url_for('task'))

#database Models--------------------------------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), index=True, unique=True)
    email = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    tasks = db.relationship('Task', backref='author', lazy='dynamic')


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(250), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, index=True, default=datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Task %r>' % self.id


#forms------------------------------------------------------------------------------------------------------------
class LoginForm(FlaskForm):
    username = StringField('Username:', validators=[InputRequired(), Length(min=4, max=16)])
    password = PasswordField('Password:', validators=[InputRequired(), Length(min=6, max=20)])
    #remember = BooleanField('remember me')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    username = StringField('Username:', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email:', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password:', validators=[InputRequired(), Length(min=8, max=20)])
    password2 = PasswordField('Confirm Password:', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')



if __name__ == '__main__':
    app.run(debug=True)




