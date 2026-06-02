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
    # Compat shims: opcli (charm-ci) hardcodes --keep-models and --model in the generated
    # pytest command (legacy pytest-operator options). These were renamed to
    # --no-juju-teardown and --juju-model in pytest-jubilant 2.0. We pass --juju-model and
    # --no-juju-teardown directly via PYTEST_ADDOPTS in spread.yaml, but we still need to
    # accept --keep-models and --model so pytest doesn't error on unrecognised options.
    parser.addoption("--keep-models", action="store_true", default=False)
    parser.addoption("--model", action="store", default=None)


def pytest_configure(config: Config) -> None:
    """Translate legacy opcli options to pytest-jubilant 2.0 equivalents.

    opcli hardcodes --keep-models and --model in the generated pytest command.
    We pass --juju-model and --no-juju-teardown directly via PYTEST_ADDOPTS in
    spread.yaml, so these shims are a fallback for any environment that does not
    set PYTEST_ADDOPTS (e.g. local runs without spread).

    Args:
        config: The pytest configuration object.
    """
    if config.getoption("--keep-models", default=False):
        config.option.no_juju_teardown = True
    model = config.getoption("--model", default=None)
    if model and not config.getoption("--juju-model", default=None):
        config.option.juju_model = model
