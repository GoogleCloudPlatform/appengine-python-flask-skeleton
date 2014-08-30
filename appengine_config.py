"""`appengine_config` gets loaded when starting a new application instance."""
import site
import os.path
import sys

# add `lib` as a site packages directory, so our `main` module can load
# third-party libraries.
#
# Because addsitedir() appends the directory, added packages might be
# ignored in favor of bundled versions earlier in the set of paths, so
# we force lib/ to the start of the list.

# break up the sys.path
sys.path, remainder = sys.path[:1], sys.path[1:]
# addsitedir is added at the beginning.
site.addsitedir(os.path.join(os.path.dirname(__file__), 'lib'))
# add the remaining paths back
sys.path.extend(remainder)
