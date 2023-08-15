# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exceptions used by the nginx-ingress-integrator charm."""


class InvalidIngressOptionError(Exception):
    def __init__(self, msg: str):
        self.msg = msg
