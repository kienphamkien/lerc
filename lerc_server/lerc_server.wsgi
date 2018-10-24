#!/usr/bin/python3

#activate_this = '/opt/lerc_server/lercenv/bin/activate_this.py'
#with open(activate_this) as file_:
#    exec(file_.read(), dict(__file__=activate_this))

import sys

if sys.version_info[0]<3:
    raise Exception("Python3 required! Current (wrong) version: '%s'" % sys.version_info)

sys.path.insert(0, '/opt/lerc/lerc_server')

from server import app as application
