import os.path
import re

from setuptools import setup, find_namespace_packages


# reading package's version (same way sqlalchemy does)
with open(
    os.path.join(
        os.path.dirname(__file__),
        'yhttp/ext/auth/', '__init__.py'
    )
) as v_file:
    package_version = \
        re.compile('.*__version__ = \'(.*?)\'', re.S)\
        .match(v_file.read())\
        .group(1)


dependencies = [
    'yhttp >= 7, < 8',
    'pyjwt',
    'redis',
]


setup(
    name='yhttp-auth',
    version=package_version,
    author='Vahid Mardani',
    author_email='vahid.mardani@gmail.com',
    url='http://github.com/yhttp/yhttp-auth',
    description='A very micro http framework.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',  # This is important!
    license='MIT',
    install_requires=dependencies,
    packages=find_namespace_packages(
        where='.',
        include=['yhttp.ext.auth'],
        exclude=['tests'],
    ),
    classifiers=[
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Development Status :: 5 - Production/Stable',
        'License :: Other/Proprietary License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
