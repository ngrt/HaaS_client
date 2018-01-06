from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
import requests
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'

@app.route('/')
def index():
    #r = requests.get('http://127.0.0.1:5000/article')
    #articles = json.loads(r.text)['articles']

    return render_template('index.html', articles=[])

@app.route('/login')
def login():
    #r = requests.get('http://127.0.0.1:5000/article')
    #articles = json.loads(r.text)['articles']

    return render_template('login.html')

if __name__ == '__main__':
    app.run(port=3000, debug=True)