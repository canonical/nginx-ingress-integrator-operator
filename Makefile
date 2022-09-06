fmt:
	@echo "Normalising python layout."
	@tox -e fmt

lint: fmt
	@echo "Running flake8"
	@tox -e lint

unittest:
	@tox -e unit

integrationtest:
	@tox -e integration

test: lint unittest integrationtest

clean:
	@echo "Cleaning files"
	@git clean -fXd

.PHONY: lint test unittest clean
