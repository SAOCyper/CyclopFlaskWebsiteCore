import imghdr
from flask import Blueprint, render_template, request, flash, redirect, url_for,send_file,session,abort
from .models import User, UserForm
from werkzeug.security import generate_password_hash, check_password_hash
from . import dbsql,create_app
from flask_login import login_user, login_required, logout_user, current_user
from .models import PostForm,Posts,SearchForm,Messages,ShoppingCart,AddProduct,Products,SLUG_CHOICES
from werkzeug.utils import secure_filename
from bs4 import *
import os , uuid ,string , random ,requests ,google.auth.transport.requests ,pathlib,smtplib,ssl,jinja2,flask
from pip._vendor import cachecontrol
from google_auth_oauthlib.flow import Flow
from pathlib import Path
from datetime import datetime
from google.oauth2 import id_token
from flask_mail import Mail, Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer,SignatureExpired
#from website.invoice import CyclopInvoice
from PIL import Image
from dotenv import load_dotenv
from os.path import dirname
import google.oauth2.credentials
import functools
from requests_oauthlib import OAuth2Session
from requests_oauthlib.compliance_fixes import facebook_compliance_fix
import googleapiclient.discovery
from authlib.integrations.flask_client import OAuth
#from authlib.integrations.requests_client import OAuth2Session


auth = Blueprint('auth', __name__,template_folder='templates')
app = create_app()
env_path =Path("website/").resolve()
env_path = os.path.join(dirname(__file__) , '.env')
load_dotenv(env_path)
oauth = OAuth(app)

mail = Mail(app)

context = ssl.create_default_context()
#invoice_gen = CyclopInvoice()
message = MIMEMultipart("alternative")
msg = EmailMessage()
s = URLSafeTimedSerializer('Thisisasecret')
GMAIL_USER = 'trcyclop@gmail.com'
GMAIL_APP_PASSWORD = 'ijbflwabtgrxgklz'
#########################################################
############## Google OAuth #####################
#########################################################

ACCESS_TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'
AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent'
AUTHORIZATION_SCOPE ='openid email profile'
AUTH_REDIRECT_URI = "http://cycloptr.com/callback"
BASE_URI ="https://cycloptr.com"
AUTH_TOKEN_KEY = 'auth_token'
AUTH_STATE_KEY = 'auth_state'

FACEBOOK_CLIENT_ID = os.environ.get('FACEBOOK_CLIENT_ID')
FACEBOOK_CLIENT_SECRET = os.environ.get('FACEBOOK_CLIENT_SECRET')
AUTHORIZATION_BASE_URL = 'https://www.facebook.com/dialog/oauth'
TOKEN_URL = 'https://graph.facebook.com/oauth/access_token'
REDIRECT_URI = 'https://cycloptr.com/'
""" facebook = OAuth2Session(FACEBOOK_CLIENT_ID, redirect_uri=REDIRECT_URI)
facebook = facebook_compliance_fix(facebook)
authorization_url, state = facebook.authorization_url(AUTHORIZATION_BASE_URL) """
def is_logged_in():
    return True if AUTH_TOKEN_KEY in flask.session else False

def build_credentials():
    if not is_logged_in():
        raise Exception('User must be logged in')

    oauth2_tokens = flask.session[AUTH_TOKEN_KEY]
    
    return google.oauth2.credentials.Credentials(
                oauth2_tokens['access_token'],
                refresh_token=oauth2_tokens['refresh_token'],
                client_id=os.environ.get('GOOGLE_CLIENT_ID'),
                client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
                token_uri=ACCESS_TOKEN_URI)

def get_user_info():
    credentials = build_credentials()

    oauth2_client = googleapiclient.discovery.build(
                        'oauth2', 'v2',
                        credentials=credentials)

    return oauth2_client.userinfo().get().execute()

def no_cache(view):
    @functools.wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = flask.make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

    return functools.update_wrapper(no_cache_impl, view)

@auth.route('/google_login')
def google_login():
	GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
	GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
	CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
	oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    # Redirect to google_auth function
	redirect_uri = url_for('auth.google_auth', _external=True)
    
	return oauth.google.authorize_redirect(redirect_uri)



@auth.route('/callback')
def google_auth():
	token = oauth.google.authorize_access_token()
	user = oauth.google.parse_id_token(token, None)
	print(" Google User ", user)
	email = user["email"]
	user_registered = User.query.filter_by(email=email).first()
	if user:
		flash('Başarıyla Giriş Yapıldı.Hoşgeldin {}'.format(user["name"]), category='success')
		login_user(user_registered, remember=True , force=True)
		return redirect(url_for('views.home'))
	else : 
		flash('Kullanıcı Bulunamadı.Lütfen Kayıt Olunuz', category='fail')
		return render_template('login.html')

@auth.route('/twitter/')
def twitter():
   
    # Twitter Oauth Config
    TWITTER_CLIENT_ID = os.environ.get('TWITTER_CLIENT_ID')
    TWITTER_CLIENT_SECRET = os.environ.get('TWITTER_CLIENT_SECRET')
    oauth.register(
        name='twitter',
        client_id=TWITTER_CLIENT_ID,
        client_secret=TWITTER_CLIENT_SECRET,
        request_token_url='https://api.twitter.com/oauth/request_token',
        request_token_params=None,
        access_token_url='https://api.twitter.com/oauth/access_token',
        access_token_params=None,
        authorize_url='https://api.twitter.com/oauth/authenticate',
        authorize_params=None,
        api_base_url='https://api.twitter.com/1.1/',
        client_kwargs=None,
    )
    redirect_uri = url_for('auth.twitter_auth', _external=True)
    return oauth.twitter.authorize_redirect(redirect_uri)
 
@auth.route('/twitter/auth/')
def twitter_auth():
    token = oauth.twitter.authorize_access_token()
    resp = oauth.twitter.get('account/verify_credentials.json')
    profile = resp.json()
    print(" Twitter User", profile)
    return redirect('/')

@auth.route('/facebook/')
def facebook():
	
	# Facebook Oauth Config
	oauth.register(
        name='facebook',
        client_id=FACEBOOK_CLIENT_ID,
        client_secret=FACEBOOK_CLIENT_SECRET,
        access_token_url='https://graph.facebook.com/oauth/access_token',
        access_token_params=None,
        authorize_url='https://www.facebook.com/dialog/oauth',
        authorize_params=None,
        api_base_url='https://graph.facebook.com/',
        client_kwargs={'scope': 'email'},

    )

	
	redirect_uri = url_for('auth.facebook_auth', _external=True)
	return oauth.oauth1_client_cls.authorize_redirect(redirect_uri)
 
@auth.route('/facebook/auth/')
def facebook_auth():
	token = oauth.authorize_access_token()
	user_registered=oauth.oauth1_client_cls.parse_id_token(token)
	""" resp = oauth.facebook.get(
        'https://graph.facebook.com/me?fields=id,name,email,picture{url}')
	profile = resp.json() """
	print("Facebook User ", user_registered)
	email = user_registered["email"]
	user_registered = User.query.filter_by(email=email).first()
	if user_registered :
		flash('Logged in successfully!', category='success')
		login_user(user_registered, remember=True , force=True)
		return redirect(url_for('views.home'))
	else:
		return render_template('login.html')
    

#########################################################
############## MAIN PAGES FUNCTIONS #####################
#########################################################
# Update Database Record
@auth.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
	form = UserForm()
	posts_for_display=post_parser()
	name_to_update = User.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.name = request.form['name']
		name_to_update.email = request.form['email']
		name_to_update.username = request.form['username']
		try:
			dbsql.session.commit()
			flash("Kullanıcı Bilgileri Başarıyla Güncellendi!")
			return render_template("update.html", 
				form=form,
				name_to_update = name_to_update, id=id,
				posts = posts_for_display)
		except:
			flash("Error!  Looks like there was a problem...try again!")
			return render_template("update.html", 
				form=form,
				name_to_update = name_to_update,
				id=id,
				posts = posts_for_display)
	else:
		return render_template("update.html", 
				form=form,
				name_to_update = name_to_update,
				id = id,
				posts = posts_for_display)


@auth.route('/delete/<int:id>')
@login_required
def delete(id):
	posts_for_display=post_parser()
	# Check logged in id vs. id to delete
	if id == current_user.id:
		user_to_delete = User.query.get_or_404(id)
		name = None
		form = UserForm()

		try:
			dbsql.session.delete(user_to_delete)
			dbsql.session.commit()
			flash("Kullanıcı Silindi!!")

			our_users = User.query.order_by(User.date_added)
			return render_template("sign_up.html", 
			form=form,
			name=name,
			our_users=our_users,
			posts = posts_for_display)

		except:
			flash("Whoops! Kullanıcı Silinirken Problem Yaşandı.Tekrar Deneyin!!")
			return render_template("sign_up.html", 
			form=form, name=name,
			posts = posts_for_display)
	else:
		flash("Bu Kullanıcıyı Silemezsiniz ")
		return redirect(url_for('auth.dashboard'))



@auth.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
	time_organizer_user()
	posts_for_display=post_parser()
	form = UserForm()
	id = current_user.id
	name_to_update = User.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.name = request.form['name']
		name_to_update.email = request.form['email']
		name_to_update.username = request.form['username']
		name_to_update.about_author = request.form['about_author']
		name_to_update.Spotify_Username = request.form['spotify_username']
		name_to_update.Spotify_Email = request.form['spotify_email']
		name_to_update.Spotify_Password = request.form['spotify_password']
		name_to_update.Netflix_Email = request.form['netflix_email']
		name_to_update.Netflix_Password = request.form['netflix_password']
		
		# Check for profile pic
		if request.files['profile_pic']:
			name_to_update.profile_pic = request.files['profile_pic']

			# Grab Image Name
			pic_filename = secure_filename(name_to_update.profile_pic.filename)
			# Set UUID
			pic_name = str(uuid.uuid1()) + "_" + pic_filename
			# Save That Image
			saver = request.files['profile_pic']
			

			# Change it to a string to save to db
			name_to_update.profile_pic = pic_name
			try:
				dbsql.session.commit()
				path =Path("website/static/images/").resolve()
				saver.save(os.path.join(path, pic_name))
				flash("Kullanıcı Bilgisi Güncellendi!")
				return render_template("dashboard.html", 
					form=form,
					name_to_update = name_to_update,
					posts = posts_for_display)
			except:
				flash("Error!  Looks like there was a problem...try again!")
				return render_template("dashboard.html", 
					form=form,
					name_to_update = name_to_update,
					posts = posts_for_display)
		else:
			dbsql.session.commit()
			flash("Kullanıcı Bilgisi Güncellendi!")
			return render_template("dashboard.html", 
				form=form, 
				name_to_update = name_to_update,
				posts = posts_for_display)
	else:
		return render_template("dashboard.html", 
				form=form,
				name_to_update = name_to_update,
				id = id,
				posts = posts_for_display)

@auth.route('/login', methods=['GET', 'POST'])
def login():
	""" authorization_url , state = flow.authorization_url() """
	""" if request.method == 'POST' or len(state)>1: """
	if request.method == 'POST':
		""" session["state"] = state """
		stock_limit = 0
		email = request.form.get('email')
		password = request.form.get('password')
		email = email.lower()
		user = User.query.filter_by(email=email).first()
		#session["user"]=user
		if user:
			if check_password_hash(user.password, password):
				
				flash('Başarıyla Giriş Yapıldu.Hoşgeldin {}'.format(user.name), category='success')
				login_user(user, remember=True)
				return redirect(url_for('views.home'))
			else:
				flash('Yanlış Şifre.Tekrar Deneyin!', category='error')
		else:
			flash('Bu Emaile Ait Kullanıcı Bulunamadı!', category='error')
	return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('auth.login'))

@auth.route('/pricing')
def pricing():
	posts_for_display=post_parser()
	return render_template("pricing.html", user=current_user, posts = posts_for_display)


@auth.route('/confirm_email/<token>/<email>/<name>/<username>/<password1>/<password2>')
def confirm_email(token,email,name,username,password1,password2):		
	try:
		email = s.loads(token, salt='email-confirm', max_age=3600)
	except SignatureExpired:
		flash("Token Süresi Doldu.Tekrar Deneyin")
		return redirect(url_for('auth.login'))
	new_user = User(email=email, name=name,username=username, password=generate_password_hash(
						password1, method='sha256'))
	
	dbsql.session.add(new_user)
	dbsql.session.commit()
	
	login_user(new_user, remember=True)
	flash('Email Doğrulaması alındı.Hesap yaratıldı!', category='success')
	return redirect(url_for('views.home'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
	if request.method == 'POST':
			
			email = request.form.get('email')
			name = request.form.get('firstName')
			username = request.form.get('username')
			password1 = request.form.get('password1')
			password2 = request.form.get('password2')
			email = email.lower()
			user = User.query.filter_by(email=email).first()
			if user:
				flash('Bu Emaile Ait Kullanıcı Zaten Var!', category='error')
			elif len(email) < 4:
				flash('Email ismi 3 karakterden fazla olmalı', category='error')
			elif len(name) < 2:
				flash('İsim 1 karakterden fazla olmalı', category='error')
			elif len(username) < 2:
				flash('Kullanıcı isimi 1 karakterden fazla olmalı', category='error')
			elif password1 != password2:
				flash('Şifreler uyuşmuyor.Tekrar Deneyin', category='error')
			elif len(password1) < 7:
				flash('Şifre en az 7 haneli olmalıdır.Tekrar Deneyiniz!', category='error')
			else:
				token = s.dumps(email, salt='email-confirm')
				link = url_for('auth.confirm_email', token=token,email=email,name=name,username=username,password1=password1,password2=password2, _external=True)
				gmail_user = 'trcyclop@gmail.com'
				gmail_app_password = 'ijbflwabtgrxgklz'
				sent_from = gmail_user
				sent_to = email
				sent_subject = "CyclopTr'ye Hoşgeldiniz!"
				sent_body = ("Hey, what's up? friend!\n\n"
							"We are happy to see you around us!\n"
							"\n"
							"Please verify your email by clicking below link.\n"
							"{}\n"
							"Cheers,\n"
							"Mert\n").format(link)

				email_text = """\
				From: %s
				To: %s
				Subject: %s

				%s
				""" % (sent_from, ", ".join(sent_to), sent_subject, sent_body)
				message["Subject"] = "Welcome to Cycloptr!"
				message["From"] = gmail_user
				message["To"] = email
				
				
				html = """\
					<html>
						<meta charset="utf-8">
						<meta http-equiv="x-ua-compatible" content="ie=edge">
						<title>Email Confirmation</title>
						<meta name="viewport" content="width=device-width, initial-scale=1">
						<body style="border: 1px solid #8b2635;background-color:#444;background:#8b2635;">
							<table border="0" cellpadding="0" cellspacing="0" width="100%">

        
								<tr>
								<td align="center" bgcolor="#e9ecef">
								
									<table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
									<tr>
										<td align="center" valign="top" style="padding: 36px 24px;">
										<a href="https://cycloptr.com" target="_blank" style="display: inline-block;">
											<img src="../website/static/images/glados.jpg" alt="Logo" border="0" width="48" style="display: block; width: 48px; max-width: 48px; min-width: 48px;height: auto;line-height: 100%;text-decoration: none;border: 0;outline: none;">
										</a>
										</td>
									</tr>
									</table>
									
								</td>
								</tr>
							
								<tr>
								<td align="center" bgcolor="#e9ecef">
									
									<table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
									<tr>
										<td align="left" bgcolor="#ffffff" style="padding: 36px 24px 0; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; border-top: 3px solid #d4dadf;">
										<h1 style="margin: 0; font-size: 32px; font-weight: 700; letter-spacing: -1px; line-height: 48px;">Email Adresi Dogrulama</h1>
										</td>
									</tr>
									</table>
									
								</td>
								</tr>
								
								<tr>
								<td align="center" bgcolor="#e9ecef">
									
									<table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">

									
									<tr>
										<td align="left" bgcolor="#ffffff" style="padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">
											<p style="margin-left:15%;font-size: 22px;font-weight: 700;">Merhaba,{}</p><br>
											<p>Senin bizlerle beraber bulunmandan memnuniyet duyuyoruz!</p><br>
											<p style="margin: 0;">Email adresi dogrulamasi icin asagidaki butona tiklayiniz. Eger <a href="https://cycloptr.com">Cycloptr</a> ile hesap yaratmadiysaniz bu maili silebilirsiniz.</p>
										</td>
									</tr>
									

									
									<tr>
										<td align="left" bgcolor="#ffffff">
										<table border="0" cellpadding="0" cellspacing="0" width="100%">
											<tr>
											<td align="center" bgcolor="#ffffff" style="padding: 12px;">
												<table border="0" cellpadding="0" cellspacing="0">
												<tr>
													<td align="center" bgcolor="#1a82e2" style="border-radius: 6px;">
													<a href="{}" target="_blank" style="display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #ffffff; text-decoration: none; border-radius: 6px;-ms-text-size-adjust: 100%;">Hesap Dogrulama</a>
													</td>
												</tr>
												</table>
											</td>
											</tr>
										</table>
										</td>
									</tr>
									
									<tr>
										<td align="left" bgcolor="#ffffff" style="padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">
										<p style="margin: 0;">Ise yaramadiysa asagidaki linki browser'a kopyalayip yapistirin.</p>
										<p style="margin: 0;"><a href="{}" target="_blank">{}</a></p>
										</td>
									</tr>
									
									<tr>
										<td align="left" bgcolor="#ffffff" style="padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px; border-bottom: 3px solid #d4dadf">
										<p style="margin: 0;">En icten dileklerimizle,<br> CyclopTeam</p>
										</td>
									</tr>
									

									</table>
									
								</td>
								</tr>
							
								<tr>
								<td align="center" bgcolor="#e9ecef" style="padding: 24px;">
									
									<table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">

									
									<tr>
										<td align="center" bgcolor="#e9ecef" style="padding: 12px 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 14px; line-height: 20px; color: #666;">
										<p style="margin: 0;">Bu maili email adresinizi dogrulamak icin aldiniz. Eger islem size ait degilse bu maili silebilirsiniz.</p>
										</td>
									</tr>
									
									<tr>
										<td align="center" bgcolor="#e9ecef" style="padding: 12px 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 14px; line-height: 20px; color: #666;">
										<p style="margin: 0;">Email almamak icin<a href="https://cycloptr.com" target="_blank"> uyeligi iptal et</a> istedigin zaman</p>
										<p style="margin: 0;">Hacettepe Universitesi Universiteler Mahallesi Hacettepe TeknoKent Ar-Ge Bina No:3 Cankaya/Ankara</p>
										</td>
									</tr>
									

									</table>
									
								</td>
								</tr>
								

							</table>
						</body>
					</html>
					""".format(username,link,link,link)
				
				part1 = MIMEText(email_text, "plain")
				part2 = MIMEText(html, "html")
				# Add HTML/plain-text parts to MIMEMultipart message
				# The email client will try to render the last part first
				message.attach(part1)
				message.attach(part2)
				""" pdf_path = r"C:\webserverflaskcyclop\invoice.pdf"
				binary_pdf = open(pdf_path,'rb')
				file_name = binary_pdf.name
				payload = MIMEBase('application', 'octate-stream', Name=file_name)
				payload.set_payload((binary_pdf).read())
				# enconding the binary into base64
				encoders.encode_base64(payload)
				# add header with pdf name
				payload.add_header('Content-Decomposition', 'attachment', filename=file_name)
				message.attach(payload) """

				try:
					server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
					
					server.login(gmail_user, gmail_app_password)
					server.sendmail(sent_from, sent_to, message.as_string())
					server.close()
					flash("Doğrulama Emaili {} adresine gönderildi!".format(email))
					return render_template("sign_up.html", user=current_user)
				except Exception as exception:
					flash("Error: %s!\n\n" % exception)

			
	return render_template("sign_up.html", user=current_user)




ALLOWED_IMAGE_EXTENSIONS=["JPEG","JPG","PNG","GIF"]
MAX_IMAGE_FILESIZE = 0.5 *1024*1024
def allowed_image(filename):

	if not "." in filename:
		return False
	
	ext = filename.rsplit(".",1)[1]
	if ext.upper() in ALLOWED_IMAGE_EXTENSIONS:
		return True
	else:
		return False
def allowed_image_filesize(filesize):

	if int(filesize or 0) <= MAX_IMAGE_FILESIZE:
		return True

	else:
		return False

@auth.route('/upload-image', methods=["GET","POST"])
@login_required
def upload_image():
	posts_for_display=post_parser()
	CameraOn = request.form.get('CameraOn')
	if request.method == "POST":
		if request.files:
			if not allowed_image_filesize(request.cookies.get("filesize")):
				print("File exceed maximum file size")
				return redirect(request.url)
			image = request.files["image"]
			if image.filename =="" and CameraOn == None:
				print("Image must have a filename")
				flash('No image selected for uploading')
				return redirect(request.url)
			if CameraOn=='CameraOn':
				return redirect(request.url)
			if image and allowed_image(image.filename):
				filename = secure_filename(image.filename)
				path =Path("website/static/uploads/").resolve()
				image.save(os.path.join(path,filename))
				print("Image Saved")
				flash('Image succesfully uploaded and displayed below')
				return render_template("upload_image.html",filename=filename,user=current_user , posts = posts_for_display)
				
			elif CameraOn!='CameraOn':
				flash('Image extensıon is not allowed')
				print("Image extensıon is not allowed")
				return redirect(request.url)
			
			
	else:    
		return render_template("upload_image.html", user=current_user , posts = posts_for_display)


@auth.route('display/<filename>',methods=["GET"])
@login_required
def display_image(filename):
	return redirect(url_for('static',filename='uploads/'+filename),code=301)


@auth.route('/terms-and-conditions', methods=["GET"])
def terms_and_conditions():
	posts_for_display=post_parser()
	return render_template("terms_and_conditions.html",user=current_user , posts = posts_for_display)

@auth.route('/privacy-policy', methods=["GET"])
def privacy():
	posts_for_display=post_parser()
	return render_template("privacy.html",user=current_user , posts = posts_for_display)
#########################################################
############## HELPER FUNCTIONS #########################
#########################################################
@auth.context_processor
def base():
	form = SearchForm()
	return dict(form=form)


def post_parser():
	posts = Posts.query.order_by(Posts.date_posted)
	date_now = datetime.utcnow()
	posts_for_display = []
	for post in posts:
		time_difference =date_now - post.date_posted
		time_difference = str(time_difference)
		if post.id <5  or "week" not in time_difference:
			posts_for_display.append(post)
		else:
			break
	return posts_for_display

def time_organizer_user():
    user = User.query.get_or_404(current_user.id)
    date_fix = ''
    date_to_organize = user.date_added
    date_to_organize = str(date_to_organize) 
    for i in date_to_organize:
        if i == '.':
            break
        date_fix = date_fix + i
    date_fix = datetime.strptime(date_fix, '%Y-%m-%d %H:%M:%S')
    user.date_added = date_fix
    dbsql.session.add(user)
    dbsql.session.commit()

def time_organizer():
	posts = Posts.query.order_by(Posts.date_posted)
	for post in posts :
		date_to_organize = post.date_posted
		date_to_organize = str(date_to_organize)
		date_fix = ''
		for i in date_to_organize:
			if i == '.':
				break
			date_fix = date_fix + i
		date_fix = datetime.strptime(date_fix, '%Y-%m-%d %H:%M:%S')
		post.date_posted = date_fix
		dbsql.session.add(post)
		dbsql.session.commit()

#########################################################
############## BLOG POST FUNCTIONS ######################
#########################################################
@auth.route('/search',methods=['POST'])
@login_required
def search():
	form =SearchForm()
	postlar=Posts.query
	posts_for_display=post_parser()
	if request.method == 'POST':
		searched = form.searched.data
		#Query Database
		postlar = postlar.filter(Posts.slug.like('%' + searched + '%'))
		postlar = postlar.order_by(Posts.title).all()
		return render_template("search.html",form=form,searched = searched,postlar = postlar ,posts = posts_for_display)

@auth.route('/add-post', methods = ['GET','POST'])
@login_required
def add_post():
	form = PostForm()
	posts_for_display=post_parser()
	if request.method == 'POST':
		poster = current_user.id
		blog_title=request.form.get("blog_title")
		blog_content=request.form.get("blog_content")
		blog_slug=request.form.get("blog_slug")
		blog_author=request.form.get("blog_author")
		slug_display = dict(SLUG_CHOICES).get(form.slug.data)
		print(slug_display)
		""" post = Posts(title = blog_title , content = blog_content ,author = blog_author ,slug =blog_slug) """
		post = Posts(title=form.title.data,slug = slug_display ,poster_id = poster,content=form.content.data)
		form.title.data= ''
		form.content.data = ''
		form.slug.data = ''
		
		dbsql.session.add(post)
		dbsql.session.commit()
		time_organizer()
		flash("Blog Post Submitted Succesfully")
	#Redirect
	return render_template("add_post.html",user=current_user,form=form,posts= posts_for_display)

@auth.route('/show-posts',methods = ['GET', 'POST'])
def show_post():
	posts_for_display=post_parser()
	if request.method == 'GET':
		postlar = Posts.query.order_by(Posts.date_posted)
	return render_template("show_post.html",user=current_user,postlar = postlar,posts=posts_for_display)

@auth.route('/posts/<int:id>')
def post(id):
	posts_for_display=post_parser()
	post = Posts.query.get_or_404(id)
	return render_template('post.html', post=post , posts= posts_for_display)

@auth.route('/posts/edit/<int:id>',methods=['GET','POST'])
@login_required
def edit_post(id):
	posts_for_display=post_parser()
	post = Posts.query.get_or_404(id)
	form = PostForm()
	if request.method=='POST':
		post.title = form.title.data
		post.slug = form.slug.data
		post.content = form.content.data
		dbsql.session.add(post)
		dbsql.session.commit()
		flash("Post has been Updated")
		return redirect(url_for('auth.add_post',id=post.id))
	if current_user.id == post.poster_id or current_user.id == 1:
		form.title.data = post.title
		form.content.data = post.content
		form.slug.data = post.slug
		return render_template('edit_post.html',form=form , posts = posts_for_display)
	else:
		flash("You can't edit this post")
		postlar = Posts.query.order_by(Posts.date_posted)
		return render_template("show_post.html",user=current_user,postlar = postlar,posts = posts_for_display)

@auth.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
	posts_for_display=post_parser()
	post_to_delete = Posts.query.get_or_404(id)
	id=current_user.id
	if id == post_to_delete.poster.id or current_user.id == 1:
		try:
			dbsql.session.delete(post_to_delete)
			dbsql.session.commit()

			flash("Blog Post was deleted!")
			
			postlar = Posts.query.order_by(Posts.date_posted)
			return render_template("show_post.html",user=current_user,postlar = postlar,posts = posts_for_display)
		except:
			flash("There was a problem while deleting!Try Again.")
			postlar = Posts.query.order_by(Posts.date_posted)
			return render_template("show_post.html",user=current_user,postlar = postlar,posts = posts_for_display)
	else :
		flash("You can't delete this element.Since it isn't yours!")    
		postlar = Posts.query.order_by(Posts.date_posted)
		return render_template("show_post.html",user=current_user,postlar = postlar,posts = posts_for_display)




#########################################################
############## EXTERNAL DEVICE FUNTIONS #################
#########################################################

@auth.route('/temperature-motion', methods=["GET","POST"])
def temp_motion():
	temperature=request.get_data()
	return temperature



#########################################################
############## ADMIN FUNTIONS ###########################
#########################################################
@auth.route('send_messages' , methods= ['GET','POST'])
def send_messages():
	if request.method == 'POST':
		name =request.form.get("name")
		email = request.form.get("email")
		subject = request.form.get("subject")
		message = request.form.get("message")
		sentmessage = Messages(name = name ,email = email ,subject = subject , message = message)
		dbsql.session.add(sentmessage)
		dbsql.session.commit()
		return redirect(url_for('views.home'))

@auth.route('/admin/delete/<int:id>' , methods = ['GET' , 'POST'])
@login_required
def delete_messages(id):
	posts_for_display=post_parser()
	post_to_delete = Messages.query.get_or_404(id)
	id=current_user.id
	if current_user.id == 1:
		try:
			dbsql.session.delete(post_to_delete)
			dbsql.session.commit()

			flash("User Message was deleted!")
			
			messages = Messages.query.order_by(Messages.sender_id)
			return render_template("admin.html",user=current_user,messages = messages,posts = posts_for_display)
		except:
			flash("There was a problem while deleting!Try Again.")
			messages = Messages.query.order_by(Messages.sender_id)
			return render_template("admin.html",user=current_user,messages = messages,posts = posts_for_display)
	else :
		flash("You can't delete this element.Since it isn't yours!")    
		messages = Messages.query.order_by(Messages.sender_id)
		return render_template("admin.html",user=current_user,messages = messages,posts = posts_for_display)

@auth.route('/admin')
@login_required
def admin():
	time_organizer()
	messages = Messages.query.order_by(Messages.sender_id)
	posts_for_display=post_parser()
	id = current_user.id
	if id == 1:
		return render_template("admin.html" ,posts = posts_for_display ,messages = messages)
	else:
		flash("Sorry You must be admin to access.")
		return redirect(url_for('views.home'))

@auth.route('/update-products/<int:id>' , methods = ['GET','POST'])
@login_required
def update_products(id):
	form = AddProduct(request.form)
	product=Products.query.get_or_404(id)
	posts_for_display=post_parser()
	path =Path("website/static/images/").resolve()
	if os.path.exists(os.path.join(path ,product.image_1)) :
		image1_path = os.path.join(path,product.image_1)
		image2_path = os.path.join(path,product.image_2)
		image3_path = os.path.join(path,product.image_3)
		condition_flag = True
	else:
		image1_path = os.path.join(path,"image.jpeg")
		image2_path = os.path.join(path,"image.jpeg")
		image3_path = os.path.join(path,"image.jpeg")
		condition_flag = False
	if request.method =='POST':
			dbsql.session.rollback()
			product.name = form.name.data
			product.price = form.price.data 
			product.stock = form.stock.data
			product.description = form.description.data
			product.discount = form.discount.data
			if condition_flag == False :
				product.image_1 = request.files['image_1']
				product.image_2 = request.files['image_2']
				product.image_3 = request.files['image_3']

				# Grab Image Name
				pic_filename1 = secure_filename(product.image_1.filename)
				pic_filename2 = secure_filename(product.image_1.filename)
				pic_filename3 = secure_filename(product.image_1.filename)
				# Set UUID
				pic_name1 = str(uuid.uuid1()) + "_" + pic_filename1
				pic_name2 = str(uuid.uuid1()) + "_" + pic_filename2
				pic_name3 = str(uuid.uuid1()) + "_" + pic_filename3
				# Save That Image
				saver1 = request.files['image_1']
				saver2 = request.files['image_2']
				saver3 = request.files['image_3']
				product.image_1 = pic_name1
				product.image_2 = pic_name2
				product.image_3 = pic_name3
				try:
					dbsql.session.add(product)
					dbsql.session.commit()
					
					saver1.save(os.path.join(path, pic_name1))
					saver2.save(os.path.join(path, pic_name2))
					saver3.save(os.path.join(path, pic_name3))
					flash("Product Images Uploaded Successfully!")
					return render_template("update_products.html",user=current_user, 
						form=form,posts = posts_for_display)
				except:
					
					flash("Error!  Looks like there was a problem...try again!")
					return render_template("update_products.html",user=current_user, 
						form=form,posts = posts_for_display)
			elif condition_flag == True:
				with dbsql.session.no_autoflush :
					try:
						dbsql.session.add(product)
						dbsql.session.commit()
						flash("Succesfully updated!")
						products = Products.query.order_by(Products.date_added)
						return render_template("show_product.html",user=current_user, 
							form=form,posts = posts_for_display,products = products)
					except:
						flash("Error!  Looks like there was a problem...try again!")
						return render_template("update_products.html",user=current_user, 
							form=form,posts = posts_for_display)
	else:
		form.name.data = product.name
		form.price.data = product.price
		form.stock.data = product.stock
		form.description.data = product.description
		form.discount.data = product.discount
		form.image_1.data = Image.open(image1_path)
		form.image_2.data = Image.open(image2_path)
		form.image_3.data = Image.open(image3_path)
		return render_template("update_products.html",user=current_user,form = form)

@auth.route('/add-products' , methods = ['GET','POST'])
@login_required
def add_products():
	form = AddProduct(request.form)
	posts_for_display=post_parser()
	if request.method == 'POST':
		product = Products(name = form.name.data,price = form.price.data ,discount = form.discount.data ,stock = form.stock.data,description =form.description.data)
		form.name.data= ''
		form.price.data = ''
		form.discount.data = ''
		form.stock.data = ''
		form.description.data = ''
		dbsql.session.add(product)
		dbsql.session.commit()
		flash("Product has been added succesfully!")
	#Redirect
	return render_template("addproduct.html",user=current_user,form=form,posts= posts_for_display)

@auth.route('/product/<int:id>' , methods = ['GET','POST'])
@login_required
def product(id):
	posts_for_display=post_parser()
	product =  Products.query.get_or_404(id)
	return render_template("product.html",user=current_user,product = product,posts=posts_for_display)

@auth.route('/show_products' , methods = ['GET','POST'])
@login_required
def show_products():
	posts_for_display=post_parser()
	if request.method == 'GET':
		products = Products.query.order_by(Products.date_added)
	return render_template("show_product.html",user=current_user,products = products,posts=posts_for_display)

@auth.route('/delete_post/<int:id>')
@login_required
def delete_products(id):
	posts_for_display=post_parser()
	product_to_delete = Products.query.get_or_404(id)
	if current_user.id == 1:
		try:
			dbsql.session.delete(product_to_delete)
			dbsql.session.commit()

			flash("Blog Post was deleted!")
			
			products = Products.query.order_by(Products.date_added)
			return render_template("show_product.html",user=current_user,products = products,posts = posts_for_display)
		except:
			flash("There was a problem while deleting!Try Again.")
			products = Products.query.order_by(Products.date_added)
			return render_template("show_product.html",user=current_user,products = products,posts = posts_for_display)
	else :
		flash("You can't delete this element.Since it isn't yours!")    
		products = Products.query.order_by(Products.date_added)
		return render_template("show_product.html",user=current_user,products = products,posts = posts_for_display)

#########################################################
############## SHOPPING CART FUNCTIONS ##################
#########################################################

@auth.route('/add_to_cart' , methods = ['GET','POST'])
def add_cart():
	posts_for_display=post_parser()
	products = Products.query.order_by(Products.date_added)
	#Redirect
	return render_template("add_cart.html",user=current_user,posts= posts_for_display,products = products)

stock_track_list = []
@auth.route('/cart_item_functions' , methods = ['GET','POST'])
@login_required
def cart_item_functions():
	_quantity = int(request.form['quantity'])
	stock_track_list.append(_quantity)
	_price = request.form['code']
	_name = request.form['name']
	users = User.query.order_by(User.id)
	for user in users:
		if current_user.id == user.id :
			client = user
	products = Products.query.order_by(Products.date_added)
	shopper = current_user.id
	buyer = current_user.id
	if request.method == 'POST' and _quantity and _price :
		for product in products:
			product_quantity = 0
			for i in stock_track_list:
				product_quantity = i + product_quantity
			#print(product_quantity)
			if client.stock_limit + _quantity < product.stock :
				cart_item = ShoppingCart(product = _name , quantity = _quantity ,price = _price ,buyer = current_user.id,shopper_id =shopper)
				dbsql.session.add(cart_item)
				dbsql.session.commit()
				flash("{} sepete başarıyla eklendi".format(_name))
				cart_items = ShoppingCart.query.order_by(ShoppingCart.buyer)
				all_price = 0
				total_quantity = 0
				session.modified = True
				card_item_price_list = []
				for card_item in cart_items:
					if card_item.buyer == current_user.id:
						card_item_price = card_item.quantity * card_item.price
						card_item_price_list.append(card_item_price)
						total_quantity = card_item.quantity + total_quantity
						all_price = card_item_price + all_price
				session["card_item_price_list"] = card_item_price_list
				session["total_quantity"]=total_quantity
				#session["stock_limit"]=total_quantity
				client.stock_limit = total_quantity
				dbsql.session.commit()
				session["all_price"]=all_price
				return redirect(url_for('auth.show_cart'))
			else:
				stock_track_list.pop()
				flash("Stokta Yeterli Sayıda Kalmadı")
				return redirect(url_for('auth.show_cart'))
	else:
		return redirect(url_for('add_to_cart'))

@auth.route('/show_card_items' , methods = ['GET','POST'])
@login_required
def show_cart():
	products = Products.query.order_by(Products.date_added)
	posts_for_display=post_parser()
	buyer = current_user.id
	total_quantity=0
	all_price=0
	
	if request.method == 'GET':
		cart_items = ShoppingCart.query.order_by(ShoppingCart.buyer)
		card_item_price_list = []
		for cart_item in cart_items:
			if cart_item.buyer == current_user.id:
				card_item_price = cart_item.quantity * cart_item.price
				card_item_price_list.append(card_item_price)
				card_item_price_single = cart_item.quantity * cart_item.price
				total_quantity = cart_item.quantity + total_quantity
				all_price = card_item_price_single + all_price
	session["card_item_price_list"] = card_item_price_list
	session["total_quantity"] = total_quantity
	session["all_price"] = all_price
	return render_template("cart_show.html",user=current_user,cart_items = cart_items,posts= posts_for_display,products =products)

@auth.route('/empty_cart' , methods = ['GET','POST'])
@login_required
def empty_cart():
	try:
		session.clear()
		return redirect(url_for('auth.show_cart'))
	except Exception as e:
		print(e)

@auth.route('/remove_cart_item/<int:id>' , methods = ['GET','POST'])
@login_required
def remove_cart_item(id):
	posts_for_display=post_parser()
	cart_item_to_delete = ShoppingCart.query.get_or_404(id)
	dbsql.session.delete(cart_item_to_delete)
	dbsql.session.commit()
	products = Products.query.order_by(Products.date_added)
	cart_items_buyer = ShoppingCart.query.order_by(ShoppingCart.buyer)
	all_price = 0
	total_quantity = 0
	users = User.query.order_by(User.id)
	for user in users:
		if current_user.id == user.id :
			client = user
	session.modified = True
	for card_item in cart_items_buyer:
		if card_item.buyer == current_user.id:
			card_item_price = card_item.quantity * card_item.price
			total_quantity = card_item.quantity + total_quantity
			all_price = card_item_price + all_price
	session["total_quantity"]=total_quantity
	session["all_price"]=all_price
	for i in stock_track_list : 
		if i == cart_item_to_delete.quantity :
			stock_track_list.remove(i)
	#print(stock_track_list)
	
	dbsql.session.commit()
	client.stock_limit = client.stock_limit - cart_item_to_delete.quantity
	dbsql.session.commit()
	#session["stock_limit"] = session["stock_limit"] - cart_item_to_delete.quantity
	flash("İtem Sepetten Başarıyla Çıkarıldı")
	card_items = ShoppingCart.query.order_by(ShoppingCart.date_added)
	return render_template("cart_show.html",user=current_user,cart_items = card_items,posts = posts_for_display,products =products)

def checkout_clear(id):
	cart_item_to_delete = ShoppingCart.query.get_or_404(id)
	dbsql.session.delete(cart_item_to_delete)
	dbsql.session.commit()
	cart_items_buyer = ShoppingCart.query.order_by(ShoppingCart.buyer)
	all_price = 0
	total_quantity = 0
	users = User.query.order_by(User.id)
	for user in users:
		if current_user.id == user.id :
			client = user
	session.modified = True
	for card_item in cart_items_buyer:
		if card_item.buyer == current_user.id:
			card_item_price = card_item.quantity * card_item.price
			total_quantity = card_item.quantity + total_quantity
			all_price = card_item_price + all_price
	session["total_quantity"]=total_quantity
	session["all_price"]=all_price
	for i in stock_track_list : 
		if i == cart_item_to_delete.quantity :
			stock_track_list.remove(i)
	#print(stock_track_list)
	client.stock_limit = client.stock_limit - cart_item_to_delete.quantity
	dbsql.session.commit()
	#session["stock_limit"] = session["stock_limit"] - cart_item_to_delete.quantity
	return True

@auth.route('/checkout',methods=['GET','POST'])
@login_required
def checkout():
	posts_for_display=post_parser()
	if request.method == 'GET':
		purchased_list_names = []
		purchased_list_prices = []
		purchased_list_quantity = []
		product_images = []
		product_names = []
		card_item_price_list=session["card_item_price_list"]
		cart_items_buyer = ShoppingCart.query.order_by(ShoppingCart.buyer)
		products = Products.query.order_by(Products.date_added)
		for product in products:
			for card_item in cart_items_buyer:
				if card_item.buyer == current_user.id:
					added_info = card_item.product + '  x' + str(card_item.quantity)
					#added_info = added_info.encode('utf-8')
					#added_info = u' '.join((card_item.product,' x',str(card_item.quantity))).encode('utf-8').strip() 
					product.name = product.name
					product.price = product.price
					product.stock = product.stock - card_item.quantity
					product.description = product.description
					product.discount = product.discount
					product.image_1 = product.image_1
					product.image_2 = product.image_2
					product.image_3 = product.image_3
					dbsql.session.commit()
					""" product_images.append(product.image_1) """
					purchased_list_names.append(added_info)
					purchased_list_prices.append(card_item.price)
					purchased_list_quantity.append(card_item.quantity)
		client_name = current_user.name
		translationTable = str.maketrans("ğĞıİöÖüÜşŞçÇ", "gGiIoOuUsScC")
		client_name_translated = client_name.translate(translationTable)
		total_quantity=session["total_quantity"]
		all_price=session["all_price"]

		


		#context =invoice_gen.create_pdf(client_name=client_name_translated,purchased_list_names=purchased_list_names,purchased_list_prices=purchased_list_prices,purchased_list_quantity = purchased_list_quantity,subtotal_list = card_item_price_list,quantity=total_quantity,price=all_price)
		
		email = current_user.email
		message["Subject"] = "Welcome to Cycloptr!"
		message["From"] = GMAIL_USER
		message["To"] = email
		template_loader = jinja2.FileSystemLoader('./')
		template_env = jinja2.Environment(loader=template_loader)
		html_template = 'post_purchase.html'
		template = template_env.get_template(html_template)		
		#output_text = template.render(context)
		output_text = "Coming Soon"
		part2 = MIMEText(output_text, "html")
		# Add HTML/plain-text parts to MIMEMultipart message
		# The email client will try to render the last part first
		message.attach(part2)
		
		

		try:
			server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
					
			server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
			server.sendmail(message["From"],message["To"], message.as_string())
			server.close()
			flash("Fatura {} adresine gönderildi!".format(email))
			#Clear card_items
			for card_item in cart_items_buyer:
				checkout_clear(card_item.id)
			return render_template("home.html", user=current_user)
		except Exception as exception:
			flash("Error: %s!\n\n" % exception)
			return render_template("home.html", user=current_user)
