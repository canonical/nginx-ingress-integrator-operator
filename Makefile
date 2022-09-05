fmt:
	@echo "Normalising python layout."
	@tox -e fmt

lint: fmt
	@echo "Running flake8"
	@tox -e lint

unittest:
	@tox -e unit

test: lint unittest

clean:
	@echo "Cleaning files"
	@git clean -fXd

.PHONY: lint test unittest clean
