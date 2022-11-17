# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import re
import subprocess  # nosec B404
import time
from pathlib import Path

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
    await ops_test.model.wait_for_idle()

    # Check that both ingress and hello-kubecon are active
    assert ops_test.model.applications[app_name].units[0].workload_status == ActiveStatus.name
    assert (
        ops_test.model.applications[hello_kubecon_app_name].units[0].workload_status
        == ActiveStatus.name
    )

    # Add required relations
    await ops_test.model.add_relation(hello_kubecon_app_name, app_name)
    await ops_test.model.wait_for_idle(status=ActiveStatus.name, idle_period=120)

    yield application


@pytest_asyncio.fixture(scope="module")
async def app_ip(app: Application):
    """Get unit IP address and add to /etc/hosts."""
    # Get the IP address which is in the status message
    ip_regex = r"[0-9]+(?:\.[0-9]+){3}"
    time.sleep(100)  # wait for ingress
    ip_address_match = re.findall(ip_regex, app.units[0].workload_status_message)
    assert (
        ip_address_match
    ), f"could not find IP address in status message: {app.units[0].workload_status_message}"
    ip_address = ip_address_match[-1]
    yield ip_address


@pytest_asyncio.fixture(scope="module")
async def app_url(app_ip: str):
    """Add to /etc/hosts."""
    ps = subprocess.Popen(["echo", f"{app_ip} hello-kubecon"], stdout=subprocess.PIPE)  # nosec
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], stdin=ps.stdout)  # nosec
    yield "http://hello-kubecon"


@pytest_asyncio.fixture(scope="module")
async def app_url_modsec(ops_test: OpsTest, app_name: str, app_url: str):
    """Enable owasp-modsecurity-crs."""
    await ops_test.juju("config", app_name, "owasp-modsecurity-crs=true")

    yield f"{app_url}/?search=../../passwords"


@pytest_asyncio.fixture(scope="module")
async def app_url_modsec_ignore(ops_test: OpsTest, app_name: str, app_url_modsec: str):
    """Add ModSecurity Custom Rule."""
    # Add ignore rule
    ignore_rule = 'SecRule REQUEST_URI "/ignore" "id:1,phase:2,nolog,allow,ctl:ruleEngine=Off"\\n'
    ignore_rule_cfg = "owasp-modsecurity-custom-rules={}".format(ignore_rule)
    await ops_test.juju("config", app_name, ignore_rule_cfg)
    app_url_modsec_ignore = app_url_modsec.replace("?", "ignore?")
    yield app_url_modsec_ignore
