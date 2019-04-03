from flask import Flask, render_template, redirect, url_for, request, url_for, flash, make_response, session
from flask_bootstrap import Bootstrap
import pandas as pd
import tablib
from flask_googlemaps import GoogleMaps
import os
from flask_wtf import Form
from flask_wtf import FlaskForm 
from wtforms.widgets import html_params, HTMLString
from wtforms import StringField, TextAreaField, TextField, SubmitField, PasswordField, SelectField, BooleanField, RadioField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from sqlalchemy.orm.attributes import flag_modified
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(15), unique=True)
	email = db.Column(db.String(50), unique=True)
	password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
	 #email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class dashboardForm(FlaskForm):
	region = SelectField('Product',choices=[('Product3','Apple-Airpods'),('Product4','Apple-iPad'),('Product2','Chanakya Corporate'),('Product1','Echo-Dot Alexa'),('Product5','LG Smart TV')])

	custom =  SubmitField(label='Search')

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password, form.password.data):
				login_user(user, remember=form.remember.data)
				return redirect(url_for('dashboard'))

		return '<h1>Invalid username or password</h1>'
		#return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

	return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = generate_password_hash(form.password.data, method='sha256')
		new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()

		return redirect(url_for('dashboard'))
		#return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

	return render_template('signup.html', form=form)

# @app.route('/dashboard')
# @login_required
# def dashboard():
# 	return render_template('dashboard.html', name=current_user.username)

@app.route('/dashboard',methods=['GET', 'POST'])
@login_required
def dashboard():

	form = dashboardForm()	
	
	dataset = tablib.Dataset()
	full_filename = ''

	
	if form.is_submitted():
		if form.region.data == 'Product1':
			df = pd.read_csv('Echo_Dot_Review.csv')
			full_filename = 'https://i.imgur.com/2bTYz0a.png'
		elif form.region.data == 'Product2':
			df = pd.read_csv('Corporate_Chanakya.csv')
			full_filename = 'https://i.imgur.com/KpC7XgV.png'
		elif form.region.data == 'Product3':
			df = pd.read_csv('Apple_iPad.csv')
			full_filename = 'https://i.imgur.com/5EXrDRT.png'
		elif form.region.data == 'Product4':
			df = pd.read_csv('Apple_Airpods.csv')
			full_filename = 'https://i.imgur.com/2YKJaAl.png'
		elif form.region.data == 'Product5':
			df = pd.read_csv('LG_SmartTV.csv')
			full_filename = 'https://i.imgur.com/1glaC8v.png'
		dataset.df = df
		h=dataset.height
		list2=[]
		for i in range(1,h+1):
			list2.append(i)
		dataset.insert_col(0, col=list2, header='Sr.no')    
	data = dataset.html
	
	return render_template('dashboard.html',user_image = full_filename,form=form, name=current_user.username, data=data)


@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))

if __name__ == '__main__':
	app.run(debug=True)