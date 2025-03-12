# How to contribute

This document explains the processes and practices recommended for contributing enhancements to the Nginx Ingress Integrator operator.

## Overview

* Generally, before developing enhancements to this charm, you should consider [opening an issue](https://github.com/canonical/nginx-ingress-integrator-operator/issues) explaining your use case.
* If you would like to chat with us about your use-cases or proposed implementation, you can reach us at [Canonical Matrix public channel](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) or [Discourse](https://discourse.charmhub.io/).
* Familiarizing yourself with the [Ops library](https://ops.readthedocs.io/en/latest/) is necessary to work on new features or bug fixes.
* All enhancements require review before being merged. Code review typically examines
   * code quality
   * test coverage
   * user experience for Juju administrators of this charm.
* Please help us out in ensuring easy to review branches by rebasing your pull request branch onto the `main` branch. This also avoids merge commits and creates a linear Git commit history.

## Developing

For any problems with this charm, please [report bugs here](https://github.com/canonical/nginx-ingress-integrator-operator/issues).

The code for this charm can be downloaded as follows:

```
git clone https://github.com/canonical/nginx-ingress-integrator-operator

```

## Test
This project uses `tox` for managing test environments. There are some pre-configured environments
that can be used for linting and formatting code when you're preparing contributions to the charm:

* `tox`: Runs all of the basic checks (`lint`, `unit`, `static`, and `coverage-report`).
* `tox -e fmt`: Runs formatting using `black` and `isort`.
* `tox -e lint`: Runs a range of static code analysis to check the code.
* `tox -e static`: Runs other checks such as `bandit` for security issues.
* `tox -e unit`: Runs the unit tests.
* `tox -e integration`: Runs the integration tests.

## Build and deploy

To build a local version of the charm, run:
```
charmcraft pack
```

Deploy using:
```bash
# Create a model
juju add-model charm-dev
# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"
# Deploy the charm (assuming you're on amd64)
juju deploy ./nginx-ingress-integrator_ubuntu-20.04-amd64.charm
```

## Canonical contributor agreement

Canonical welcomes contributions to the Nginx Ingress Integrator Operator. Please check out our [contributor agreement](https://ubuntu.com/legal/contributors) if you’re interested in contributing to the solution.