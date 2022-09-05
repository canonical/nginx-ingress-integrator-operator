#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import re

import pytest
import requests
from ops.model import ActiveStatus, Application


@pytest.mark.asyncio
@pytest.mark.abort_on_fail
async def test_active(app: Application):
    """
    arrange: given charm has been built and connected to another unit
    act: when the status is checked
    assert: then the workload status is active.
    """
    assert app.units[0].workload_status == ActiveStatus.name


@pytest.mark.asyncio
@pytest.mark.abort_on_fail
async def test_reachable(app: Application):
    """
    arrange: given charm has been built and connected to another unit
    act: when other unit-s service is queried via the ingress
    assert: then the reasponse is HTTP 200 OK.
    """
    # Get the IP address which is in the status message
    ip_regex = r"[0-9]+(?:\.[0-9]+){3}"
    ip_address_match = re.search(ip_regex, app.units[0].workload_status_message)
    assert ip_address_match, "could not find IP address in status message"
    ip_address = ip_address_match.group(0)
    port = "8080"

    response = requests.get(f"http://{ip_address}:{port}")

    assert response.status_code == 200
