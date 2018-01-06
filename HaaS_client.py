from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
import requests
from requests.auth import HTTPBasicAuth
import json
from wtforms import *
from wtforms.validators import *
from flask_wtf import *
from functools import wraps
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sealdarethebest'

#class of WTForms forms
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

class HashForm(Form):
    data = StringField('Text to hash', validators=[InputRequired()])
    algo = SelectField('Choose a method', choices=[('md5', 'md5'), ('sha1', 'sha1'), ('sha256', 'sha256')], validators=[InputRequired()])
    iteration = IntegerField('Number of iteration', validators=[InputRequired()])

#decorator to require the token of the API and return the current_user information
def require_token(func):
    @wraps(func)
    def check_token(*args, **kwargs):
        if 'token' not in session:
            return jsonify({'message': 'Not Authorized'}), 401

        try:
            data = jwt.decode(session['token'], app.config['SECRET_KEY'])
            headers = {'x-access-token': session['token']}
            r = requests.get('http://127.0.0.1:5000/user/{}'.format(data['public_id']), headers=headers)
            current_user = json.loads(r.text)['user']
        except:
            return jsonify({'message': 'Not Authorized'}), 401

        return func(current_user, *args, **kwargs)

    return check_token


#decorator check if the user is connected - accessible for all the views
@app.context_processor
def inject_isloggedin():
    if 'token' not in session:
        return {'isloggedin' : False}

    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'])
        headers = {'x-access-token': session['token']}
        r = requests.get('http://127.0.0.1:5000/user/{}'.format(data['public_id']), headers=headers)
        current_user = json.loads(r.text)['user']
        return {'isloggedin' : True, 'current_user' : current_user}
    except:
        return {'isloggedin' : False}

#index route to hash a data
@app.route('/', methods=['GET', 'POST'])
def index():
    hashForm = HashForm()

    if hashForm.validate_on_submit():
        payload = {'data': hashForm.data.data, 'algo': hashForm.algo.data, 'iteration': int(hashForm.iteration.data)}
        headers = {'x-access-token': session['token']}
        r = requests.post('http://127.0.0.1:5000/calculateHash', json=payload, headers=headers)
        hash = "Your hash is {}".format(json.loads(r.text)['hash'])
        flash(hash)
        return redirect(url_for('index'))

    return render_template('index.html', hashForm=hashForm)

#login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        r = requests.get('http://127.0.0.1:5000/login', auth=HTTPBasicAuth(loginForm.email.data, loginForm.password.data))
        if r.text == "Could not verify":
            flash(r.text)
        elif json.loads(r.text)['token']:
            session['token'] = json.loads(r.text)['token']
            flash("You are logged in")
            return redirect(url_for('index'))

    return render_template('login.html', loginForm=loginForm)

#logout route
@app.route('/logout', methods=['GET', 'POST'])
@require_token
def logout(current_user):
    session.pop('token', None)
    return redirect(url_for('index'))

#register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    registerUserForm = RegisterUserForm()
    if registerUserForm.validate_on_submit():
        payload = {'email': registerUserForm.email.data, 'name': registerUserForm.name.data, 'password': registerUserForm.password.data}

        r = requests.post('http://127.0.0.1:5000/register', json=payload)
        message = json.loads(r.text)['message']
        flash(message)
        return redirect(url_for('index'))
    return render_template('register.html', registerUserForm=registerUserForm)

if __name__ == '__main__':
    app.run(port=3000, debug=True)