# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exceptions used by the nginx-ingress-integrator charm."""


class InvalidIngressOptionError(Exception):
    """Custom error that indicates invalid ingress option.

    Args:
        msg: error message.
    """

    def __init__(self, msg: str):
        """Construct the InvalidIngressOptionError object.

        Args:
            msg: error message.
        """
        self.msg = msg
