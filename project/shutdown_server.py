# %%
import sys, errno
import os
from flask import Flask
from project.constant import SERVER
app = Flask(__name__)

@app.route('/shutdown')
def shutdown():
    os.system(f'kill -9 `lsof -t -i:{SERVER.HTTP_SERVER_PORT}`')
    os.system(f'kill -9 `lsof -t -i:{SERVER.HTTPS_SERVER_PORT}`')
    sys.exit(errno.EINTR)