PKG_NAMESPACE = yhttp.ext.auth
PKG_NAME = yhttp-auth
PYTEST_FLAGS = -vv
PYDEPS_COMMON = \
	'coveralls' \
	'freezegun' \
	'bddrest >= 4, < 5' \
	'bddcli >= 2.5.1, < 3' \
	'yhttp-dev >= 3.1.3'

include make/common.mk
include make/venv.mk
include make/install.mk
include make/lint.mk
include make/test.mk
include make/dist.mk
include make/pypi.mk
