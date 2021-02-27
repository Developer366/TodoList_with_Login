from flask_wtf import FlaskForm
from wtforms import * #Stringfields, submitfield, etc.
from wtforms.validators import DataRequired, InputRequired, Email, Length, ValidationError, EqualTo, email_validator
from Modules.models import User

#Kamil Peza Login and Register Forms:
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

