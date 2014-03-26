## Python Flask-Classy, Flask Template for Google App Engine


-> Python (https://www.python.org/)
-> Flask (http://flask.pocoo.org/)
-> Flask-Classy (http://pythonhosted.org/Flask-Classy/)
-> Google App Engine (https://developers.google.com/appengine/)
-> Bootstrap 3 (http://getbootstrap.com/)
-> Gae Session (https://github.com/dound/gae-sessions)


Features:
    * Simple Regiter and Login Functionality
    * Session integration functionality using GAESESSION
    * Boostrap 3 template


Fork Repo: git clone https://github.com/GoogleCloudPlatform/appengine-python-flask-skeleton.git


A skeleton for building Python applications on Google App Engine with the
[Flask micro framework](http://flask.pocoo.org).

See our other [Google Cloud Platform github
repos](https://github.com/GoogleCloudPlatform) for sample applications and
scaffolding for other python frameworks and use cases.

## Run Locally
1. Install the [App Engine Python SDK](https://developers.google.com/appengine/downloads).
See the README file for directions. You'll need python 2.7 and [pip 1.4 or later](http://www.pip-installer.org/en/latest/installing.html) installed too.

2. Clone this repo with

   ```
   git clone https://github.com/rileonard15/appengine-python-flask-skeleton.git
   ```
3. Install dependencies in the project's lib directory.
   Note: App Engine can only import libraries from inside your project directory.

   ```
   cd appengine-python-flask-skeleton
   pip install -r requirements.txt -t lib
   ```
4. Run this project locally from the command line:

   ```
   dev_appserver.py .
   ```

Visit the application [http://localhost:8080](http://localhost:8080)


## Author
Leonard Mark Dimayuga
