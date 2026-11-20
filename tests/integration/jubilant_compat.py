# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Select the jubilant flavour matching the Juju version the tests run against.

The Juju 2 tox environment installs jubilant-backports, which supports the Juju 2.9 CLI and
status format. The Juju 3 environment only installs jubilant.
"""

try:
    import jubilant_backports as jubilant

    JUJU2 = True
except ImportError:
    import jubilant

    JUJU2 = False

__all__ = ["JUJU2", "jubilant"]
