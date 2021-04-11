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

#routes-----------------------------------------------------------------------------------------------------------------

@app.route('/', methods=['GET', 'POST']) #login route
def login():

    if current_user.is_authenticated:
        return redirect(url_for('task'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid Username or Password')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('task'))
    return render_template('login.html', title='Log In ', form=form)

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

    tasks = db.session.query(Task).filter_by(user_id=current_user.id).filter_by(completed='0').all()
    #tasks = db.session.query(Task).filter_by(completed='False')
    completed = db.session.query(Task).filter_by(user_id=current_user.id).filter_by(completed='1').all()

    return render_template('Task.html', tasks=tasks, completed=completed, title='List of Tasks')

@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == "POST":
        new_task = request.form['task']
        now = datetime.now()
        add_task = Task(task=new_task, date_created=now, completed=False, user_id=current_user.id)

        try:
            db.session.add(add_task)
            db.session.commit()
            return redirect(url_for('task'))
        except:
            return 'There was an issue with adding your task =['

    else:
        tasks = db.session.query(Task).all()
        return render_template('Task.html', tasks=tasks)


@app.route('/delete/<int:id>', methods=['GET','POST'])
def delete(id):
    task_to_delete = Task.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/task')
    except:
        return "There was a problem deleting task"

@app.route('/completed/<int:id>', methods=['GET', 'POST'])
def complete(id):
    task_to_complete = Task.query.get_or_404(id)
    #num_rows_updated = Task.query.filter_by(completed='0').update(Task(completed='1'))
    now = datetime.now()

    try:
        task_to_complete.completed = True
        task_to_complete.date_completed = now
        #task_to_complete['completed'] = '1'
        #task_to_complete.update(Task.completed)
        #db.session.update()
        db.session.commit()
        return redirect('/task')
    except:
        return "There was a problem with completing your task :["
    
    #return render_template("Task.html", task_to_completed= task_to_completed)

#database Models--------------------------------------------------------------------------------------------------------
class User(UserMixin, db.Model):
#tablename= user
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
#tablename = task
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(250), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, index=True, default=datetime.now())
    date_completed = db.Column(db.DateTime, index=True, default=datetime.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Task %r>' % self.id


#forms------------------------------------------------------------------------------------------------------------------
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




