from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LanguageForm(FlaskForm):
    language = SelectField('Select Language', choices=[('en', 'English'), ('es', 'Spanish'), ('fr', 'French')], validators=[DataRequired()])
    submit = SubmitField('Select')

class ChatForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    model = SelectField('Model', choices=[('default', 'Default Model'), ('advanced', 'Advanced Model')], validators=[DataRequired()])
    submit = SubmitField('Send')
