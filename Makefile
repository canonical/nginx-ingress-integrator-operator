blacken:
	@echo "Normalising python layout with black."
	@tox -e black

lint: blacken
	@echo "Running flake8"
	@tox -e lint

# We actually use the build directory created by charmcraft,
# but the .charm file makes a much more convenient sentinel.
unittest: nginx-ingress-integrator_ubuntu-20.04-amd64.charm
	@tox -e unit

test: lint unittest

clean:
	@echo "Cleaning files"
	@git clean -fXd

nginx-ingress-integrator_ubuntu-20.04-amd64.charm: src/*.py requirements.txt
	charmcraft build

.PHONY: lint test unittest clean
