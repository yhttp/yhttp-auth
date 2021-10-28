# yhttp-auth

[![PyPI](http://img.shields.io/pypi/v/yhttp-auth.svg)](https://pypi.python.org/pypi/yhttp-auth)
[![Build](https://github.com/yhttp/yhttp-auth/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/yhttp/yhttp-auth/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/yhttp/yhttp-auth/badge.svg?branch=master)](https://coveralls.io/github/yhttp/yhttp-auth?branch=master)


Authentication extension for [yhttp](https://github.com/yhttp/yhttp).


### Install

```bash
pip install yhttp-pony
```


### Usage

```python
from yhttp import Application
from yhttp.ext.auth import install as auth_install


app = Application()
auth = auth_install(app)
app.settings.merge(f'''
auth:
  redis:
    host: localhost
    port: 6379
    db: 0

  token:
    algorithm: HS256
    secret: foobar

  refresh:
    key: yhttp-refresh-token
    algorithm: HS256
    secret: quxquux
    secure: true
    httponly: true
    maxage: 2592000  # 1 Month
    domain: example.com
''')


@app.route('/reftokens')
@yhttp.statuscode(yhttp.statuses.created)
def create(req):
    app.auth.set_refreshtoken(req, 'alice', dict(baz='qux'))

@app.route('/tokens')
@yhttp.statuscode(yhttp.statuses.created)
@yhttp.text
def refresh(req):
    reftoken = app.auth.verify_refreshtoken(req)
    return app.auth.dump_from_refreshtoken(reftoken, dict(foo='bar'))

@app.route('/admin')
@auth(roles='admin, god')
@yhttp.text
def get(req):
    return req.identity.roles

app.ready()
```

### Command line interface

setup.py

```python

setup(
    ...
    entry_points={
        'console_scripts': [
            'myapp = myapp:app.climain'
        ]
    },
    ...
)

```

```bash
myapp auth --help
```
