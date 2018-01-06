from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
import requests
import json
from wtforms import *
from wtforms.validators import *
from flask_wtf import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'

class CreateArticleForm(Form):
    title = StringField('Title', [InputRequired()])
    body = TextAreaField('Text', [InputRequired()])

class RegisterUserForm(Form):
    email = StringField('Email', [InputRequired()])
    name = StringField('Name', [InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(),
                                                     EqualTo('password_confirmation', message='Passwords must match'),
                                                     Length(min=5)])
    password_confirmation = PasswordField('Password confirmation', validators=[InputRequired()])

class LoginForm(Form):
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])


@app.route('/')
def index():
    #r = requests.get('http://127.0.0.1:5000/article')
    #articles = json.loads(r.text)['articles']

    return render_template('index.html', articles=[])

@app.route('/login')
def login():
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        r = requests.get('http://127.0.0.1:5000/login', auth=HTTPBasicAuth(loginForm.email.data, loginForm.password.data))

        if json.loads(r.text)['token']:
            session['token'] = json.loads(r.text)['token']
            flash("You are logged in")
            return redirect(url_for('index'))

    return render_template('login.html', loginForm=loginForm)

@app.route('/logout', methods=['GET', 'POST'])
#@require_token
def logout(current_user):
    session.pop('token', None)
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    registerUserForm = RegisterUserForm()
    return render_template('register.html', registerUserForm=registerUserForm)

if __name__ == '__main__':
    app.run(port=3000, debug=True)