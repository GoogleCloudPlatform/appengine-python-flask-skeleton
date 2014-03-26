"""`main` is the top level module for your Flask application."""

# Import the Flask Framework
from flask import Flask, render_template, request, redirect
from flask.flask_classy import FlaskView, route, _FlaskViewMeta
import jinja2, os, datetime, base64, hashlib, logging, string, random
from gaesessions import get_current_session

# MODELS
from models import User, Session

app = Flask(__name__)
# Note: We don't need to call run() since our application is embedded within
# the App Engine WSGI application server.

jinja_environment = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), autoescape=True)

# FUNCTIONS:

def hash_password(email, password):
    i = email + password + "6caba898-51f8-4b19-9f81-fa1dd7131b08"
    return base64.b64encode(hashlib.sha1(i).digest())

def normalize_id(this_id):
    new_id = ""
    try:
        new_id = int(this_id)
    except:
        new_id = this_id

    return new_id

def create_token(email):
    key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(5))

    i = email + key + "6caba898-51f8-4b19-9f81-fa1dd7131b08"

    return base64.b64encode(hashlib.sha1(i).digest())



class Basehandler(FlaskView):
    def initializer(self, request=None, response=None, dct=None):

        self.tv = {}
        self.session = ""
        self.now = datetime.datetime.now()
        self.session = self.get_session()
        self.user = self.get_current_user()

    def this_render(self, template=None, data=None):
        if self.user:
            self.tv["user"] = self.user.to_object()

        template = jinja_environment.get_template(template)
        return template.render(self.tv)

    def get_session(self):
        return get_current_session()

    def get_current_user(self):
        if self.session.has_key("token"):
            session = Session.get_by_id(self.session["token"])
            return session.user.get()
        else:
            return None

    def login(self, user):
        token = create_token(user.email)
        session = Session(id=token)
        session.token = token
        session.user = user.key
        session.put()

        self.session["token"] = token

        return

    def logout(self):
        session = get_current_session()
        if session.is_active():
            session.terminate()
            return redirect("/")


class FrontView(Basehandler):
    route_base = '/'

    def get(self):
        self.initializer()
        self.tv["current_page"] = "FRONT"
        return self.this_render("frontend/index.html")


class RegisterView(Basehandler):
    def get(self):
        self.initializer()
        self.tv["current_page"] = "REGISTER"
        self.tv["new"] = "Guest"

        return self.this_render("frontend/register.html")

    def post(self):
        self.initializer()
        email = request.form['email'].strip()
        name = request.form['name']
        password = request.form['password']

        logging.critical(email)
        logging.critical(name)

        user = User(id=email)
        user.name = name
        user.email = email
        user.password = hash_password(email, password)

        user.put()

        self.login(user)
        return redirect("/dashboard/")


class LoginView(Basehandler):
    def get(self):
        self.initializer()
        self.tv["current_page"] = "LOGIN"
        self.tv["new"] = "Guest"

        return self.this_render("frontend/login.html")

    def post(self):
        self.initializer()
        self.tv["current_page"] = "LOGIN"

        email = request.form['email'].strip()
        password = request.form['password']

        user = User.get_by_id(normalize_id(email))

        if user:
            if user.password == hash_password(email, password):
                self.tv["new"] = user.name
                self.login(user)
                return redirect("/dashboard/")
            else:
                return "INVALID PASSWORD"
        else:
            return "INVALID EMAIL"


class LogoutView(Basehandler):
    def get(self):
        self.initializer()
        self.tv["current_page"] = "LOGOUT"

        self.logout()


class DashboardView(Basehandler):
    def get(self):
        self.initializer()
        self.tv["current_page"] = "DASHBOARD"

        return self.this_render("frontend/dashboard.html")


@app.errorhandler(404)
def page_not_found(e):
    """Return a custom 404 error."""
    return 'Sorry, Nothing at this URL.', 404


@app.errorhandler(500)
def page_not_found(e):
    """Return a custom 500 error."""
    return 'Sorry, unexpected error: {}'.format(e), 500




""" ROUTES HANDLER """

FrontView.register(app)
RegisterView.register(app)
LoginView.register(app)
DashboardView.register(app)
LogoutView.register(app)


