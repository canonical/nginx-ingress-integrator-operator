# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# mypy: disable-error-code="union-attr"
# pylint: disable=redefined-outer-name,subprocess-run-check,consider-using-with

"""General configuration module for integration tests."""
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import List

import kubernetes
import pytest_asyncio
import yaml
from ops.model import ActiveStatus, Application
from pytest import fixture
from pytest_operator.plugin import OpsTest

# Mype can't recognize the name as a string type, so we should skip the type check.
ACTIVE_STATUS_NAME = ActiveStatus.name  # type: ignore[has-type]


@fixture(scope="module")
def metadata():
    """Provide charm metadata."""
    yield yaml.safe_load(Path("./metadata.yaml").read_text(encoding="utf8"))


@fixture(scope="module")
def app_name(metadata):
    """Provide app name from the metadata."""
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
    model_app = ops_test.model.applications[app_name]
    app_status = model_app.units[0].workload_status
    assert app_status == ACTIVE_STATUS_NAME
    model_hello = ops_test.model.applications[hello_kubecon_app_name]
    hello_status = model_hello.units[0].workload_status
    assert hello_status == ACTIVE_STATUS_NAME

    # Add required relations
    await ops_test.model.add_relation(hello_kubecon_app_name, app_name)
    await ops_test.model.wait_for_idle(timeout=10 * 60, status=ACTIVE_STATUS_NAME)
    yield application


@pytest_asyncio.fixture(scope="module")
async def ip_address_list(ops_test: OpsTest, app: Application):
    """Get unit IP address from workload message.

    Example: Ingress IP(s): 127.0.0.1, Service IP(s): 10.152.183.84
    """
    # Reduce the update_status frequency until the cluster is deployed
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(status="active")
    # Mypy does not recognize the units attribute of the app, so we need to skip the type check.
    status_message = app.units[0].workload_status_message  # type: ignore[attr-defined]
    ip_regex = r"[0-9]+(?:\.[0-9]+){3}"
    ip_address_list = re.findall(ip_regex, status_message)
    assert ip_address_list, f"could not find IP address in status message: {status_message}"
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
    host_line = f"{ingress_ip} hello-kubecon"
    proc_echo = subprocess.Popen(["echo", host_line], stdout=subprocess.PIPE)  # nosec
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], stdin=proc_echo.stdout)  # nosec
    yield "http://hello-kubecon"


@pytest_asyncio.fixture(scope="module")
async def app_url_modsec(ops_test: OpsTest, app_name: str, app_url: str):
    """Enable owasp-modsecurity-crs."""
    async with ops_test.fast_forward():
        await ops_test.juju("config", app_name, "owasp-modsecurity-crs=true")
        active = ACTIVE_STATUS_NAME
        await ops_test.model.wait_for_idle(status=active, timeout=60)
    yield f"{app_url}/?search=../../passwords"


@pytest_asyncio.fixture(scope="module")
async def app_url_modsec_ignore(ops_test: OpsTest, app_name: str, app_url_modsec: str):
    """Add ModSecurity Custom Rule."""
    ignore_rule = 'SecRule REQUEST_URI "/" "id:1,phase:2,nolog,allow,ctl:ruleEngine=Off"\\n'
    ignore_rule_cfg = f"owasp-modsecurity-custom-rules={ignore_rule}"
    async with ops_test.fast_forward():
        await ops_test.juju("config", app_name, ignore_rule_cfg)
        active = ACTIVE_STATUS_NAME
        await ops_test.model.wait_for_idle(status=active, timeout=60)
    yield app_url_modsec


@fixture(scope="module")
def run_action(ops_test: OpsTest):
    """Create a async function to run action and return results."""

    async def _run_action(application_name, action_name, **params):
        application = ops_test.model.applications[application_name]
        action = await application.units[0].run_action(action_name, **params)
        await action.wait()
        return action.results

    return _run_action


@fixture(scope="module")
def wait_for_ingress(ops_test: OpsTest):
    """Create an async function, that will wait until ingress resource with certain name exists."""
    kubernetes.config.load_kube_config()
    kube = kubernetes.client.NetworkingV1Api()

    async def _wait_for_ingress(ingress_name):
        await ops_test.model.block_until(
            lambda: ingress_name
            in [
                ingress.metadata.name
                for ingress in kube.list_namespaced_ingress(ops_test.model_name).items
            ],
            wait_period=5,
            timeout=10 * 60,
        )

    return _wait_for_ingress


@fixture(scope="module")
def get_ingress_annotation(ops_test: OpsTest):
    """Create a function that will retrieve all annotation from a ingress by its name."""
    assert ops_test.model
    kubernetes.config.load_kube_config()
    kube = kubernetes.client.NetworkingV1Api()
    model_name = ops_test.model_name

    def _get_ingress_annotation(ingress_name: str):
        return kube.read_namespaced_ingress(
            ingress_name, namespace=model_name
        ).metadata.annotations

    return _get_ingress_annotation


@pytest_asyncio.fixture(scope="module")
async def wait_ingress_annotation(ops_test: OpsTest, get_ingress_annotation):
    """Create an async function that will wait until certain annotation exists on ingress."""
    assert ops_test.model

    async def _wait_ingress_annotation(ingress_name: str, annotation_name: str):
        await ops_test.model.block_until(
            lambda: annotation_name in get_ingress_annotation(ingress_name),
            wait_period=5,
            timeout=300,
        )

    return _wait_ingress_annotation
