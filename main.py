#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import re
from google.appengine.ext import db
import hmac
import hashlib

#set up template globals
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

secret = 'd239d8h329dh8qyhduhaihd389h8ytjfq09hr4807fhw9u3ih4fywg9fuq9hf89h4q94'

##--------------Regular Expressions--------------##
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)
##--------------User Data------------##
class User(db.Model):
    username = db.StringProperty(required = True)
    hashed_password = db.StringProperty(required = True)    
    joined = db.DateTimeProperty(auto_now = True)
    email = db.StringProperty()
    
    @classmethod
    def get_user(cls,user):
        return db.GqlQuery("SELECT * FROM User WHERE username = :1", user).get()

##-------------Page Data-------------##
class Page(db.Model):
    path = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now=True)
    content = db.TextProperty(required=True)

    @classmethod
    def get_page(cls,path):
        return db.GqlQuery("SELECT * FROM Page WHERE path = :1 ORDER BY created DESC",path)

##--------------Handler------------##


class Handler(webapp2.RequestHandler):
    def write(self,message):
        self.response.out.write(message)

    def render(self,template,**kw):
        holder = jinja_env.get_template(template)
        self.write(holder.render(kw,user = self.user))        

    def hash(self,arg):          
        return hmac.new(secret,arg,hashlib.sha256).hexdigest()

    def make_cookie(self,val):
        return ("%s|%s" %(val,self.hash(val)))
    def set_cookie(self,val):        
        self.response.headers.add_header("Set-Cookie","username = %s;Path=/"%str(self.make_cookie(val)))
    def remove_cookie(self):
        self.response.headers.add_header("Set-Cookie","username =;Path=/")
    def read_cookie(self):        
        c = self.request.cookies.get("username")
        return c

    def initialize(self,*a,**kw):
        webapp2.RequestHandler.initialize(self,*a,**kw)
        hold = self.read_cookie() 
        if hold:
            self.user = hold.split('|')[0]
        else:
            self.user = None
            
class Signup(Handler):
    def get(self):
        if self.user:
            self.redirect('/')
        else:
            self.render('signup.html')
    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        errors = {}
        
        if not valid_username(username):
            have_error = True
            errors["username_error"] = "Username is not valid"
        if not valid_password(password):
            have_error = True
            errors["password_error"] = "Password is not valid"
        if password!= verify:
            have_error = True
            errors["verify_error"] = "Passwords do not match"
        if not valid_email(email):
            have_error = True
            errors["email_error"] = "Email is not valid"
        if db.GqlQuery("select * from User where username = :1",username).get():
            have_error = True
            errors["username_error"] = "Username is already in use"        
        if have_error:
            self.render('signup.html',**errors)
        if not have_error:            
            a = User(username = username, hashed_password = self.hash(password), email = email) 
            a.put()
            self.set_cookie(username)
            self.redirect('/')

class Login(Handler):
    def get(self):
        if self.user:
            self.redirect('/')
        else:
            self.render('login.html')
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        a = User.get_user(username)        
        errors = {}
        error = False
        if not a:
            errors["username_error"] = "Username does not exist"
            error = True
        if a:
            if not self.hash(password) == a.hashed_password:
                errors["password_error"] = "That password is incorrect"
                error = True
        if not error:
            self.set_cookie(username)
            self.redirect('/')
        self.render('login.html',**errors)           

class Logout(Handler):
    def get(self):
        self.remove_cookie()
        self.redirect('/')

class WikiPage(Handler):
    def get (self,path):        
        page = Page.get_page(path)
        hold = list(page)
        version = self.request.get('v')
        if hold:            
            if version:
                content = hold[int(version)].content        
            else:
                content = hold[0].content
            self.render('content.html',path=path,content = content)
            
        else:
            self.redirect('/_edit%s'%path)

class EditPage(Handler):
    def get (self,path):
        if not self.user:
            self.redirect('/')  
        page = Page.get_page(path)
        hold = list(page)
        version = self.request.get('v')  
        if hold:
            if version:
                content = hold[int(version)].content        
            else:
                content = hold[0].content            
            self.render('newpage.html',path=path,content = content)
        else:
            self.render('newpage.html',path=path)

    def post(self,path):
        content = self.request.get('content')
        version = self.request.get('v')
        a = Page(path=path,content = content)
        a.put()
        self.redirect('%s'% path)

class HistoryPage(Handler):
    def get (self,path):
        hold = Page.get_page(path)
        pages = list(hold)
        self.render('history.html',path=path,pages = pages)

class CrossDomain(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'application/xml; charset=us-ascii'
        self.response.out.write(xml)
        
xml =  """<?xml version="1.0" ?>
        <cross-domain-policy>
        <allow-access-from domain="*" />
        </cross-domain-policy>"""


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/crossdomain.xml', CrossDomain),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history'+PAGE_RE,HistoryPage),
                                (PAGE_RE, WikiPage)
                               ],
                              debug=True)



