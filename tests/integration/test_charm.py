# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import re
import time

import pytest
import requests
from ops.model import ActiveStatus, Application


@pytest.mark.asyncio
@pytest.mark.abort_on_fail
async def test_active(app: Application):
    """
    arrange: given charm has been built, deployed and related to a dependent application
    act: when the status is checked
    assert: then the workload status is active.
    """
    assert app.units[0].workload_status == ActiveStatus.name


@pytest.mark.asyncio
@pytest.mark.abort_on_fail
async def test_reachable(app: Application):
    """
    arrange: given charm has been built, deployed and related to a dependent application
    act: when the dependent application is queried via the ingress
    assert: then the response is HTTP 200 OK.
    """
    # Get the IP address which is in the status message
    ip_regex = r"[0-9]+(?:\.[0-9]+){3}"
    time.sleep(100)
    ip_address_match = re.findall(ip_regex, app.units[0].workload_status_message)
    assert (
        ip_address_match
    ), f"could not find IP address in status message: {app.units[0].workload_status_message}"
    ip_address = ip_address_match[-1]
    port = "8080"

    response = requests.get(f"http://{ip_address}:{port}")

    assert response.status_code == 200
