#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module containing helpers for the charm module."""

import re


def invalid_hostname_check(hostname: str) -> bool:
    """Check if the hostname is valid according to RFC 1123.

    Args:
        hostname: Ingress hostname

    Returns:
        if the hostname is valid or not
    """
    # This regex comes from the error message kubernetes shows when trying to set an
    # invalid hostname.
    # See https://github.com/canonical/nginx-ingress-integrator-operator/issues/2
    # for an example.
    result = re.fullmatch(
        "[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*", hostname
    )
    if result:
        return True
    return False


def is_backend_protocol_valid(backend_protocol: str) -> bool:
    """Check if the backend protocol is valid.

    Args:
        backend_protocol: Ingress hostname

    Returns:
        if the backend protocol is accepted or not
    """
    accepted_values = ("HTTP", "HTTPS", "GRPC", "GRPCS", "AJP", "FCGI")
    return backend_protocol in accepted_values
