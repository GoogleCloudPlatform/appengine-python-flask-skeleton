#!/usr/bin/env bash

set -e  # If occur any error, exit

function to_console {
    echo -e "\n*** $1 ***\n"
}

cd $(dirname $0)

to_console "creating virtual env on venv folder"
python2 -m virtualenv .

to_console "Activating virtualenv"
source bin/activate

to_console "Checking up dependencies"
if [ ! -z "$1" ]
    then
        to_console "Running with proxy "$1
        pip install -r dev_requirements.txt --proxy=$1
    else
        to_console 'Runing with no proxy'
        pip install -r dev_requirements.txt
fi

cd ../appengine

if [ -d lib ]; then
    rm lib
fi
to_console "Creating symlink on /appengine/lib so installed libs become visible to Google App Engine"
ln -s ../venv/lib/python2.7/site-packages lib
