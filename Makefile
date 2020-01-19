

.PHONY=cover

cover:
	pytest --cov=yhttp.extensions.auth tests

