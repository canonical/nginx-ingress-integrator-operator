# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test charm file."""

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
    assert app.units[0].workload_status == ActiveStatus.name  # type: ignore[attr-defined,has-type]


@pytest.mark.asyncio
@pytest.mark.abort_on_fail
async def test_service_reachable(service_ip: str):
    """
    arrange: given charm has been built, deployed and related to a dependent application
    act: when the dependent application is queried via the service
    assert: then the response is HTTP 200 OK.
    """
    port = "8080"
    response = requests.get(f"http://{service_ip}:{port}", timeout=300)

    assert response.status_code == 200


@pytest.mark.asyncio
@pytest.mark.abort_on_fail
async def test_ingress_reachable(app_url: str):
    """
    arrange: given charm has been built, deployed and related to a dependent application
    act: when the dependent application is queried via the ingress
    assert: then the response is HTTP 200 OK.
    """
    response = requests.get(app_url, timeout=300)

    assert response.status_code == 200


@pytest.mark.asyncio
@pytest.mark.abort_on_fail
async def test_owasp_modsecurity_crs(app_url_modsec: str):
    """
    arrange: given charm has been built, deployed, related to a dependent application
        and owasp-modsecurity-crs is set to True
    act: when the dependent application is queried via the ingress with malicious request
    assert: then the response is HTTP 403 Forbidden for any request
    """
    response = requests.get(app_url_modsec, timeout=300)
    assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.abort_on_fail
async def test_owasp_modsecurity_custom_rules(app_url_modsec_ignore: str):
    """
    arrange: given charm has been built, deployed, related to a dependent application,
        owasp-modsecurity-crs is set to True and owasp-modsecurity-custom-rules has ignore rule
    act: when the dependent application is queried via the ingress with malicious request
    assert: then the response is HTTP 200 OK.
    """
    response = requests.get(app_url_modsec_ignore, timeout=300)
    assert response.status_code == 200
