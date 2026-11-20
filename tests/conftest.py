# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for Nginx-ingress-integrator charm tests."""

from pytest import Parser


def pytest_addoption(parser: Parser) -> None:
    """Parse additional pytest options.

    Args:
        parser: Pytest parser.
    """
    parser.addoption("--charm-file", action="store")
    parser.addoption("--model-arch", action="store")
    # Passed by operator-workflows.
    parser.addoption("--keep-models", action="store_true", default=False)
    parser.addoption("--model", action="store", default=None)
