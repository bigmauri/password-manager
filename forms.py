from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Conferma Password',
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrati')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username già in uso. Scegli un username diverso.')

class LoginForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Accedi')

class AddPasswordForm(FlaskForm):
    name = StringField('Nome Servizio (es. Google, Facebook)',
                        validators=[DataRequired(), Length(min=2, max=100)])
    username_entry = StringField('Username/Email per il servizio',
                                 validators=[DataRequired(), Length(min=2, max=100)])
    password_entry = PasswordField('Password per il servizio', validators=[DataRequired()])
    master_password = PasswordField('Master Password', validators=[DataRequired()])
    submit = SubmitField('Aggiungi Password')

class EditPasswordForm(FlaskForm):
    name = StringField('Nome Servizio (es. Google, Facebook)',
                        validators=[DataRequired(), Length(min=2, max=100)])
    username_entry = StringField('Username/Email per il servizio',
                                 validators=[DataRequired(), Length(min=2, max=100)])
    password_entry = PasswordField('Nuova Password (Lascia vuoto per non cambiare)')
    master_password = PasswordField('Master Password (Necessaria per salvare)', validators=[DataRequired()])
    submit = SubmitField('Aggiorna Password')
