# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# mypy: disable-error-code="union-attr"
# pylint: disable=redefined-outer-name,subprocess-run-check,consider-using-with,duplicate-code

"""General configuration module for integration tests."""
import json
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import List

import kubernetes
import pytest_asyncio
import yaml
from juju.model import Model
from ops.model import ActiveStatus, Application
from pytest import fixture
from pytest_operator.plugin import OpsTest

# Mype can't recognize the name as a string type, so we should skip the type check.
ACTIVE_STATUS_NAME = ActiveStatus.name  # type: ignore[has-type]
ANY_APP_NAME = "any"
INGRESS_APP_NAME = "ingress"
NEW_HOSTNAME = "any.other"
NEW_INGRESS = "any-other-ingress"
NEW_PORT = 18080


@fixture(scope="module")
def metadata():
    """Provide charm metadata."""
    yield yaml.safe_load(Path("./metadata.yaml").read_text(encoding="utf8"))


@fixture(scope="module")
def app_name(metadata):
    """Provide app name from the metadata."""
    yield metadata["name"]


@pytest_asyncio.fixture(scope="module", name="model")
async def model_fixture(ops_test: OpsTest) -> Model:
    """The current test model."""
    assert ops_test.model
    return ops_test.model


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
    host_line = f"{ingress_ip} {NEW_HOSTNAME}"
    proc_echo = subprocess.Popen(["echo", host_line], stdout=subprocess.PIPE)  # nosec
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], stdin=proc_echo.stdout)  # nosec
    yield f"http://{NEW_HOSTNAME}"


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


@pytest_asyncio.fixture(scope="module")
async def build_and_deploy_ingress(model: Model, ops_test: OpsTest):
    """Create an async function to build the nginx ingress integrator charm then deploy it."""

    async def _build_and_deploy_ingress():
        charm = await ops_test.build_charm(".")
        return await model.deploy(
            str(charm), application_name="ingress", series="focal", trust=True
        )

    return _build_and_deploy_ingress


@pytest_asyncio.fixture(scope="module")
async def deploy_any_charm(model: Model):
    """Create an async function to deploy any-charm.

    The function accepts a string as the initial src-overwrite configuration.
    """

    async def _deploy_any_charm(src_overwrite):
        await model.deploy(
            "any-charm",
            application_name="any",
            channel="beta",
            config={"src-overwrite": src_overwrite},
        )

    return _deploy_any_charm


@pytest_asyncio.fixture(scope="module")
async def build_and_deploy(model: Model, run_action, build_and_deploy_ingress, deploy_any_charm):
    """build and deploy nginx-ingress-integrator charm.

    Also deploy and relate an any-charm application for test purposes.

    Returns: None.
    """
    path_lib = "lib/charms/nginx_ingress_integrator/v0/ingress.py"
    ingress_lib = Path(path_lib).read_text(encoding="utf8")
    any_charm_script = Path("tests/integration/any_charm.py").read_text(encoding="utf8")
    any_charm_src_overwrite = {
        "ingress.py": ingress_lib,
        "any_charm.py": any_charm_script,
    }
    await deploy_any_charm(json.dumps(any_charm_src_overwrite))
    application = await build_and_deploy_ingress()
    await model.wait_for_idle()
    await run_action(ANY_APP_NAME, "rpc", method="start_server")
    relation_name = f"{INGRESS_APP_NAME}:ingress"
    await model.add_relation(ANY_APP_NAME, relation_name)
    await model.wait_for_idle(status=ACTIVE_STATUS_NAME)
    yield application


@pytest_asyncio.fixture(scope="module")
async def setup_new_hostname_and_port(ops_test, run_action, wait_for_ingress):
    """Update the service-hostname to NEW_HOSTNAME and service-port to NEW_PORT via any-charm.

    Returns: None.
    """
    rpc_return = await run_action(
        ANY_APP_NAME, "rpc", method="start_server", kwargs=json.dumps({"port": NEW_PORT})
    )
    assert json.loads(rpc_return["return"]) == NEW_PORT
    await run_action(
        ANY_APP_NAME,
        "rpc",
        method="update_ingress",
        kwargs=json.dumps(
            {"ingress_config": {"service-hostname": NEW_HOSTNAME, "service-port": NEW_PORT}}
        ),
    )
    await ops_test.model.wait_for_idle(status="active")
    await wait_for_ingress(NEW_INGRESS)
