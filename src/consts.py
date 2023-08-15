# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Constants used by the nginx-ingress-integrator charm."""

import re

_INGRESS_SUB_REGEX = re.compile("[^0-9a-zA-Z]")
CREATED_BY_LABEL = "nginx-ingress-integrator.charm.juju.is/managed-by"
BOOLEAN_CONFIG_FIELDS = ["rewrite-enabled"]
# We set this value to be unique for this deployed juju application
# so we can use it to identify resources created by this charm
REPORT_INTERVAL_COUNT = 100
INVALID_HOSTNAME_MSG = (
    "Invalid ingress hostname. The hostname must consist of lower case "
    "alphanumeric characters, '-' or '.'."
)
INVALID_BACKEND_PROTOCOL_MSG = (
    "Invalid backend protocol. Valid values: HTTP, HTTPS, GRPC, GRPCS, AJP, FCGI"
)
