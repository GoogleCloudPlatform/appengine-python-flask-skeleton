"""`appengine_config` gets loaded when starting a new application instance."""
appstats_CALC_RPC_COSTS = True

import sys
import os.path
from gaesessions import SessionMiddleware

# add `lib` subdirectory to `sys.path`, so our `main` module can load
# third-party libraries.

def webapp_add_wsgi_middleware(app):
    from google.appengine.ext.appstats import recording
    app = recording.appstats_wsgi_middleware(app)

    # To generate the cookie_key below, run the following:
    # ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$%^&*()-=+_[]}{;:'/.,<>?") for x in range(100))
    app = SessionMiddleware(app, cookie_key="!LHa-PU;Jtaitvd1#EXmKmDhP}Z43CXDNf3:qizp!O}Vzv['LU:P<f*UF]ro.wA10<qZ&1JIcW{Pgp&v{TPJ8eH.qI,0+P2?3=Tf")
    return app


sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))