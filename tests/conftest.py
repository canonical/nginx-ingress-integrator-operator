# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for Nginx-ingress-integrator charm tests."""

from pytest import Config, Parser


def pytest_addoption(parser: Parser) -> None:
    """Parse additional pytest options.

    Args:
        parser: Pytest parser.
    """
    parser.addoption("--charm-file", action="store")
    parser.addoption("--model-arch", action="store")
    # Compat shim: operator-workflows passes --keep-models, which was renamed
    # to --no-juju-teardown in pytest-jubilant 2.0. Remove once operator-workflows
    # is updated.
    parser.addoption("--keep-models", action="store_true", default=False)


def pytest_configure(config: Config) -> None:
    """Translate --keep-models to --no-juju-teardown for pytest-jubilant 2.0.

    Remove once canonical/operator-workflows passes --no-juju-teardown
    instead of --keep-models.

    Args:
        config: The pytest configuration object.
    """
    if config.getoption("--keep-models", default=False):
        config.option.no_juju_teardown = True
