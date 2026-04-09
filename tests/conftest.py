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
    # Compat shims: operator-workflows passes --keep-models and --model, which were
    # renamed to --no-juju-teardown and --juju-model in pytest-jubilant 2.0.
    # Remove once operator-workflows is updated.
    parser.addoption("--keep-models", action="store_true", default=False)
    parser.addoption("--model", action="store", default=None)


def pytest_configure(config: Config) -> None:
    """Translate legacy pytest-operator options to pytest-jubilant 2.0 equivalents.

    Remove once canonical/operator-workflows passes --no-juju-teardown
    and --juju-model instead of --keep-models and --model.

    Args:
        config: The pytest configuration object.
    """
    if config.getoption("--keep-models", default=False):
        config.option.no_juju_teardown = True
    model = config.getoption("--model", default=None)
    if model:
        config.option.juju_model = model
