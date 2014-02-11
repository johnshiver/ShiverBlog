import os
import re
import random
import hashlib
import hmac
from string import letters
import json

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
			autoescape = True)

#used to create password hash 
#steve mentioned that he wouldnt store the secret in the same file
#fine for right now  
secret = 'tasteycrumb'

#looks like its used in BlogHandler 
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

#returns value and its hash (with a secret, so people cant easily reverse engineer hash)
def make_secure_val(val): 
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#validates a secure val  
def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
	
	#sets cookie to secure value of val 
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	#checks to see if there is cookie in the request
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		#if there is a cookie, and it is valid, returns cookie_val
		return cookie_val and check_secure_val(cookie_val)

	
	#sets cookie using user_id 
	def login(self, user): 
		self.set_secure_cookie('user_id', str(user.key().id()))

	#logs user out by setting the cookie (user_id) equal to nothing
	def logout(self): 
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	#initialize is a function that gets called before every request in googleappengine
	#checks for user cookie, which was called user_id 
	#if it exists, store in self.user the actual user object 
	#check User.by_id in the User database object
	def initialize(self, *a, **kw): 
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

	def render_json(self, d):
		json_text = json.dumps(d)
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		self.response.out.write(json_text)

	

##Used in one of the templates
def render_post(response, post):
	response.out.write('<b>' + post.subject + '</b><br>')
	response.out.write(post.content)

class BlogPost(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	#replaces new lines with breaks, fixes spacing format for HTML 
	def render(self):
		self._render_text  = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

class BlogFront(BlogHandler): 
	def get(self):
		posts = db.GqlQuery("select * from BlogPost order by created desc limit 5")
		self.render('front.html', posts = posts)

class PostPage(BlogHandler): 
	def get(self, post_id): 
		 key = db.Key.from_path('BlogPost', int(post_id))
		 post = db.get(key)

		 if not post: 
		 	self.error(404)
		 	return

		 self.render("permalink.html", post = post)

class NewPost(BlogHandler):
	def get(self):
		self.render("newpost.html")

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content: 
			p = BlogPost(subject = subject, content = content)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else: 
			error = "subject and content, please!"
			self.render("newpost.html", subject = subject, content = content, error = error)

class BlogJSON(BlogHandler):
	def get(self): 
		posts = db.GqlQuery("select * from BlogPost order by created desc limit 5")
		json_dump = []
		for p in posts: 
			d = {}
			d['subject'] = p.subject
			d['content'] = p.content
			json_dump.append(d)
		self.render_json(json_dump)

class PostJSON(BlogHandler): 
	def get(self, post_id): 
		key = db.Key.from_path('BlogPost', int(post_id))
		post = db.get(key)
		d = {}
		d['subject'] = post.subject
		d['content'] = post.content 
		self.render_json(d)

################################################
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
################################################



################################################
# 				USER STUFF                     #
################################################


#makes a string of 5 random letters for pw salt 
def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

#uses salt to create hashed version of name + pw + salt
#instead of storing a user's pw, this is what goes in the database
def make_pw_hash(name, pw, salt = None): 
	if not salt: 
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

#checks to see if user / pw matches the database hash 
def valid_pw(name, password, h): 
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

#datastore object for Users
class User(db.Model):
	username = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	#@classmethod is a decorator 
	#get_by_id is a built in database function
	@classmethod
	def by_id(cls, uid): 
		return User.get_by_id(uid) 

	#filters for user by username
	#returns the user if in database
	@classmethod
	def by_name(cls, username): 
		u = User.all().filter('username =', username).get()
		return u

	#creates a new user object 
	#creats a pw hash, and then the user object (but doesnt store it)
	@classmethod
	def register(cls, username, pw, email = None): 
		pw_hash = make_pw_hash(username, pw)
		return User(username = username, 
					pw_hash = pw_hash,
					email = email)

	#if user is a valid user 
	#and the password is valid
	#returns the user object 
	@classmethod
	def login(cls, username, pw): 
		u = cls.by_name(username)
		if u and valid_pw(username, pw, u.pw_hash):
			return u

class Signup(BlogHandler):
    def get(self):
        self.render('signup.html')

    def post(self): 
    	
    	have_error = False

    	self.username = self.request.get('username')
    	self.password = self.request.get('password')
    	self.verify = self.request.get('verify')
    	self.email = self.request.get('email')

        params = dict(username = self.username,
        			  email = self.email)

    	if not valid_username(self.username):
    		params["error_username"] = "That's not a valid username."
    		have_error = True

    	if not valid_password(self.password):
    		params["error_password"] = "That wasn't a valid password."
    		have_error = True
    	elif self.password  != self.verify: 
    		params["error_verify"] = "Your passwords didn't match."
    		have_error = True

    	if not valid_email(self.email): 
    		params["error_email"] = "That's not a valid email."
    		have_error = True

    	if have_error: 
    		self.render('signup.html', **params)
        else: 
            self.done()

    def done(self, *a, **kw): 
    	raise NotImplementedError

class Register(Signup):
	def done(self):
		#make sure the user_name doesnt already exist
		u = User.by_name(self.username)
		if u: 
			msg = 'That user already exists.'
			self.render('signup.html', error_username = msg)
		else: 
			u = User.register(self.username, self.password, self.email)
			u.put()

			#login function sets the cookie, then redirects to welcome page 
			self.login(u)
			self.redirect('/blog/welcome')


class WelcomeHandler(BlogHandler):
	def get(self):
		#self.user reads cookie, makes sure its valid, sets user to self.user
		if self.user:
			self.render('welcome.html', username = self.user.username)
		else: 
			self.redirect('/blog/signup')

class Login(BlogHandler): 
	def get(self): 
		self.render('login-form.html')

	def post(self): 
		username = self.request.get('username')
		password = self.request.get('password')

		#returns user if valid username / password combination
		u = User.login(username, password)
		if u: 
			self.login(u)
			self.redirect('/blog/welcome')
		else: 
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)

class Logout(BlogHandler): 
	def get(self): 
		self.logout()
		self.redirect('/blog/signup')

app = webapp2.WSGIApplication([
    (r'/blog', BlogFront),
    (r'/blog/newpost', NewPost), 
    (r'/blog/([0-9]+)', PostPage),
    (r'/blog/signup', Register),
    (r'/blog/welcome', WelcomeHandler),
    (r'/blog/login', Login),
    (r'/blog/logout', Logout),
    (r'/blog/?.json', BlogJSON), 
    (r'/blog/([0-9]+)?.json', PostJSON) 
    ],	
    debug=True)
