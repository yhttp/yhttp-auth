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
jwt:
  secret: 12345678
''')


@app.route()
@auth()
@text
def get(req):
    with pytest.raises(AttributeError):
        req.identity.invalidattribute

    return req.identity.name


@app.route('/admin')
@auth(roles='admin, god')
@json
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
myapp jwt --help
```
