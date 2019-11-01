import json
import base64
import logging
import random
import urllib
import uuid
from datetime import datetime, date, timedelta
import webapp2
from google.appengine.ext import ndb
from libs.bcrypt import bcrypt
from google.appengine.api import urlfetch
from google.appengine.api.urlfetch_errors import *
from google.appengine.ext import vendor
vendor.add('libs')


# [START MODEL]
class EventModel(ndb.Model):
	name = ndb.StringProperty()
	date = ndb.DateProperty()


class UserModel(ndb.Model):
	username = ndb.StringProperty()
	password = ndb.StringProperty()
	email = ndb.StringProperty()


root_user_key = ndb.Key(UserModel, 'root')
pwd_hash = bcrypt.hashpw('root', bcrypt.gensalt())
UserModel(key=root_user_key, username='root', password=pwd_hash, email='111@gmail.com').put()
user_key = ndb.Key(UserModel, 'test')
pwd_hash = bcrypt.hashpw('test', bcrypt.gensalt())
UserModel(key=user_key, username='test', password=pwd_hash, email='222@gmail.com').put()


class SessionModel(ndb.Model):
	token = ndb.StringProperty()
	username = ndb.StringProperty()
	expiration = ndb.DateTimeProperty()


class SecretModel(ndb.Model):
	name = ndb.StringProperty()
	client_secret = ndb.StringProperty()


CLIENT_KEY = ndb.Key(SecretModel, 'oidc')
# [END MODEL]


# [START EVENT]
class GetEvent(webapp2.RequestHandler):
	def get(self):
		tok = self.request.cookies.get("session")
		session_key = ndb.Key("SessionModel", tok)
		session = session_key.get()
		user_key = ndb.Key("UserModel", session.username)

		events = []
		for eventModel in EventModel.query(EventModel.date >= datetime.today()).order(EventModel.date).iter():
			str1 = str(eventModel.key.parent()).split('\'')[3]
			str2 = str(user_key).split('\'')[3]
			print("str1: " + str1 + " str2: " + str2)
			if str1 == str2:
				date_str = eventModel.date.strftime('%m/%d/%Y')
				days = str(eventModel.date - date.today())
				events.append(dict(
					user=str2,
					name=eventModel.name,
					date=date_str,
					days_left=days[:-9],
					id=eventModel.key.urlsafe()
				))

		self.response.write(json.dumps(dict(events=events, error=None)))


class AddEvent(webapp2.RequestHandler):
	def post(self):
		data = json.loads(self.request.body)
		tok = self.request.cookies.get("session")
		session_key = ndb.Key("SessionModel", tok)
		session = session_key.get()
		userKey = ndb.Key("UserModel", session.username)
		print('user', userKey)
		new_id = ndb.Model.allocate_ids(size=1, parent=userKey)[0]
		print('new_id', new_id)
		event_key = ndb.Key('EventModel', new_id, parent=userKey)
		EventModel(
			name=data['name'],
			date=datetime.strptime(data['date'], '%m-%d-%Y'),
			id=1,
			parent=event_key).put()


class DeleteEvent(webapp2.RequestHandler):
	def delete(self, event_id):
		key = ndb.Key(urlsafe=event_id)
		key.delete()


# [END EVENT]


# [START MainPage]
class MainPage(webapp2.RequestHandler):
	def get(self):
		token = self.request.cookies.get("session")
		if not token:
			logging.info("Cookie not found")
			return self.redirect("/login")

		session_key = ndb.Key("SessionModel", token)
		session = session_key.get()
		if not session:
			logging.warning('Cookie invalid')
			return self.redirect("/login")

		if session.expiration < datetime.now():
			logging.warning("Token expired")
			return self.redirect("/login")

		user = ndb.Key("UserModel", session.username).get()
		if not user:
			session_key.delete()
			logging.warning("No session for current user")
			return self.redirect("/login")

		self.response.write(open("index.html").read())


# [END MainPage]


# [START LOGIN & LOGOUT]
class Login(webapp2.RequestHandler):
	def get(self):
		self.response.set_cookie('oidc_state', str(uuid.uuid4()))
		self.response.set_cookie('oidc_nonce', str(uuid.uuid4()))
		self.response.write(open("login.html").read())

	def post(self):

		old_tok = self.request.cookies.get("session")
		if old_tok:
			ndb.Key("SessionModel", old_tok).delete()
		username = self.request.get("username")
		password = self.request.get("password")

		user = ndb.Key(UserModel, username).get()

		if not user:
			params = urllib.urlencode({"error": "Bad username! Please try again."})
			self.redirect("/login?" + params)
			return

		for val in UserModel.query(UserModel.username == username):
			if val.password != bcrypt.hashpw(password, val.password):
				self.response.status = "401"
				params = urllib.urlencode({"error": "Incorrect password! Please try again."})
				self.redirect("/login?" + params)
				return
			if username == 'root':
				tok = str(0)
			else:
				ran_tok = random.randint(201, 300)
				tok = str(ran_tok)
			expiration = datetime.now() + timedelta(hours=1)
			SessionModel(key=ndb.Key("SessionModel", tok), token=tok, username=username, expiration=expiration).put()

			self.response.set_cookie('session', tok)
			self.redirect('/')


class LogOut(webapp2.RequestHandler):
	def post(self):
		token = self.request.cookies.get("session")
		if token:
			ndb.Key("SessionModel", token).delete()
			self.response.delete_cookie("session")
		self.redirect("/login")
# [END LOGIN & LOGOUT]


# [START SIGNUP]
class SignUp(webapp2.RequestHandler):
	def get(self):
		self.response.write(open("signup.html").read())

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		user = ndb.Key(UserModel, username).get()
		if user:
			params = urllib.urlencode({"error": "The username is already taken, please choose another"})
			self.redirect("/signup?" + params)
			return

		UserModel(key=user_key, username=username, password=bcrypt.hashpw(password, bcrypt.gensalt())).put()
		tok = str(random.randint(201, 300))
		expiration = datetime.now() + timedelta(hours=1)
		SessionModel(key=ndb.Key("SessionModel", tok), token=tok, username=username, expiration=expiration).put()
		self.response.set_cookie('session', tok)
		self.redirect('/')
# [END SIGNUP]


# [START MIGRATE]
class Migrate(webapp2.RequestHandler):
	def get(self):
		tok = self.request.cookies.get("session")
		session = ndb.Key("SessionModel", tok).get()
		user_key = ndb.Key("UserModel", session.username)
		if user_key == root_user_key:
			self.response.status = "401"
			return

		for val in EventModel.query((EventModel.date >= datetime.today())).order(EventModel.date).iter():
			logging.info(val.key.parent())
			str1 = str(val.key.parent()).split('\'')[3]
			str2 = str(root_user_key).split('\'')[3]
			if str1 == str2:
				new_id = ndb.Model.allocate_ids(size=1, parent=user_key)[0]
				event_key = ndb.Key('EventModel', new_id, parent=user_key)
				EventModel(name=val.name, date=val.date, id=1, parent=event_key).put()


# [END MIGRATE]

def create_session(resp, userid, ttl=timedelta(hours=1)):
	tok = str(uuid.uuid4())
	exp = datetime.now() + ttl
	key = ndb.Key(SessionModel, tok)
	SessionModel(key=key, token=tok, username=userid, expiration=exp).put()
	resp.set_cookie('session', tok, expires=exp)
	return tok


# [START OIDCAUTH]
class OIDCAuth(webapp2.RequestHandler):
	CLIENT_ID = "572396995965-d6fshqhndku0oiejap026regbrj1g10t.apps.googleusercontent.com"

	def get(self):
		code = self.request.params['code']
		state = self.request.params['state']
		state_cookie = self.request.cookies.get('oidc_state')
		nonce_cookie = self.request.cookies.get('oidc_nonce')
		self.response.delete_cookie('oidc_state')
		self.response.delete_cookie('oidc_nonce')

		if state != state_cookie:
			self.response.status = '401 invalid state'
			logging.warning('Invalid State')
			return

		secret = CLIENT_KEY.get()
		if not secret:
			self.response.status = '404 no client secret'
			logging.warning('No client secret')
			return

		logging.info("CLIENT SECRET: " + str(secret.client_secret))

		params = urllib.urlencode({
			"code": code,
			"client_id": self.CLIENT_ID,
			"client_secret": secret.client_secret,
			"redirect_uri": self.request.host_url + "/oidcauth",
			"grant_type": "authorization_code",
		})

		request_url = "https://www.googleapis.com/oauth2/v4/token"
		try:
			headers = {'Content-Type': 'application/x-www-form-urlencoded'}
			result = urlfetch.fetch(
				url=request_url,
				payload=params,
				method=urlfetch.POST,
				headers=headers,
				validate_certificate=True)
		except urlfetch.Error as err:
			logging.warning("something wrong")
			return

		fields = json.loads(result.content)
		if 'error' in fields:
			logging.warning("ERROR")
			self.response.status_int = 500
			self.response.write(result.content)
			return

		print(json.dumps(fields, indent=4))
		_, body, _ = fields['id_token'].split('.')
		body += '=' * (-len(body) % 4)
		claims = json.loads(base64.urlsafe_b64decode(body.encode('utf-8')))

		if nonce_cookie != claims['nonce']:
			self.response.write(json.dumps("Nonce does not match: expect {!r} but got {!r}".format(nonce_cookie, claims['nonce'])))
		self.response.delete_cookie('oidc_state')
		self.response.delete_cookie('oidc_nonce')

		uid = claims['sub']
		print ('uid: ' + str(uid))
		email = claims['email']
		print ('email: ' + str(email))
		ukey = ndb.Key(UserModel, uid)
		if not ukey.get():
			UserModel(key=ukey, username=uid, password="<oidc>", email=email).put()
		create_session(self.response, uid)
		self.redirect('/')
# [END OIDCAUTH]

ROUTES = [
	('/', MainPage),
	('/login', Login),
	('/signup', SignUp),
	('/events', GetEvent),
	('/event', AddEvent),
	('/delete/(.*)', DeleteEvent),
	('/logout', LogOut),
	('/migrate', Migrate),
	('/oidcauth', OIDCAuth),
]
app = webapp2.WSGIApplication(ROUTES, debug=True)





