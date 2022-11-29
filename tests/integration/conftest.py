# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import re
import subprocess  # nosec B404
from pathlib import Path
from typing import List

import pytest_asyncio
import yaml
from ops.model import ActiveStatus, Application
from pytest import fixture
from pytest_operator.plugin import OpsTest


@fixture(scope="module")
def metadata():
    """Provides charm metadata."""
    yield yaml.safe_load(Path("./metadata.yaml").read_text())


@fixture(scope="module")
def app_name(metadata):
    """Provides app name from the metadata."""
    yield metadata["name"]


@pytest_asyncio.fixture(scope="module")
async def app(ops_test: OpsTest, app_name: str):
    """Build ingress charm used for integration testing.

    Builds the charm and deploys it and a charm that depends on it.
    """
    # Deploy relations first to speed up overall execution
    hello_kubecon_app_name = "hello-kubecon"
    await ops_test.model.deploy(hello_kubecon_app_name)

    # Build and deploy ingress
    charm = await ops_test.build_charm(".")
    application = await ops_test.model.deploy(
        charm, application_name=app_name, series="focal", trust=True
    )
    await ops_test.model.wait_for_idle(timeout=10 * 60)

    # Check that both ingress and hello-kubecon are active
    assert ops_test.model.applications[app_name].units[0].workload_status == ActiveStatus.name
    assert (
        ops_test.model.applications[hello_kubecon_app_name].units[0].workload_status
        == ActiveStatus.name
    )

    # Add required relations
    await ops_test.model.add_relation(hello_kubecon_app_name, app_name)
    await ops_test.model.wait_for_idle(timeout=10 * 60)

    yield application


@pytest_asyncio.fixture(scope="module")
async def ip_address_list(ops_test: OpsTest, app: Application):
    """Get unit IP address from workload message.

    Example: Ingress IP(s): 127.0.0.1, Service IP(s): 10.152.183.84
    """
    # Reduce the update_status frequency until the cluster is deployed
    async with ops_test.fast_forward():
        await ops_test.model.block_until(
            lambda: "Ingress IP(s)" in app.units[0].workload_status_message, timeout=100
        )
    ip_regex = r"[0-9]+(?:\.[0-9]+){3}"
    ip_address_list = re.findall(ip_regex, app.units[0].workload_status_message)
    assert (
        ip_address_list
    ), f"could not find IP address in status message: {app.units[0].workload_status_message}"
    yield ip_address_list


@pytest_asyncio.fixture(scope="module")
async def service_ip(ip_address_list: List):
    """Last match is the service IP."""
    yield ip_address_list[-1]


@pytest_asyncio.fixture(scope="module")
async def ingress_ip(ip_address_list: List):
    """First match is the ingress IP."""
    yield ip_address_list[0]


@pytest_asyncio.fixture(scope="module")
async def app_url(ingress_ip: str):
    """Add to /etc/hosts."""
    ps = subprocess.Popen(["echo", f"{ingress_ip} hello-kubecon"], stdout=subprocess.PIPE)  # nosec
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], stdin=ps.stdout)  # nosec
    yield "http://hello-kubecon"


@pytest_asyncio.fixture(scope="module")
async def app_url_modsec(ops_test: OpsTest, app_name: str, app_url: str):
    """Enable owasp-modsecurity-crs."""
    async with ops_test.fast_forward():
        await ops_test.juju("config", app_name, "owasp-modsecurity-crs=true")
        await ops_test.model.wait_for_idle(status=ActiveStatus.name, timeout=60)
    yield f"{app_url}/?search=../../passwords"


@pytest_asyncio.fixture(scope="module")
async def app_url_modsec_ignore(ops_test: OpsTest, app_name: str, app_url_modsec: str):
    """Add ModSecurity Custom Rule."""
    ignore_rule = 'SecRule REQUEST_URI "/" "id:1,phase:2,nolog,allow,ctl:ruleEngine=Off"\\n'
    ignore_rule_cfg = f"owasp-modsecurity-custom-rules={ignore_rule}"
    async with ops_test.fast_forward():
        await ops_test.juju("config", app_name, ignore_rule_cfg)
        await ops_test.model.wait_for_idle(status=ActiveStatus.name, timeout=60)
    yield app_url_modsec


@fixture
def run_action(ops_test: OpsTest):
    """Create a async function to run action and return results."""

    async def _run_action(application_name, action_name, **params):
        application = ops_test.model.applications[application_name]
        action = await application.units[0].run_action(action_name, **params)
        await action.wait()
        return action.results

    return _run_action
