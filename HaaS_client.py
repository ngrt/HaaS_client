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

@app.context_processor
def inject_isloggedin():
    if 'token' not in session:
        return {'isloggedin' : False}

    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'])
        print(data)
        headers = {'x-access-token': session['token']}
        r = requests.get('http://127.0.0.1:5000/user/{}'.format(data['public_id']), headers=headers)
        current_user = json.loads(r.text)['user']
        print(current_user['id'])
        return {'isloggedin' : True, 'current_user' : current_user}
    except:
        return {'isloggedin' : False}



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        r = requests.get('http://127.0.0.1:5000/login', auth=HTTPBasicAuth(loginForm.email.data, loginForm.password.data))
        if r.text == "Could not verify":
            flash(r.text)
        elif json.loads(r.text)['token']:
            print(json.loads(r.text)['token'])
            session['token'] = json.loads(r.text)['token']
            flash("You are logged in")
            return redirect(url_for('index'))

    return render_template('login.html', loginForm=loginForm)

@app.route('/logout', methods=['GET', 'POST'])
@require_token
def logout(current_user):
    session.pop('token', None)
    return redirect(url_for('index'))

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