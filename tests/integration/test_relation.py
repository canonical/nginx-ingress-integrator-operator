import asyncio
import json
from pathlib import Path
from typing import List

import kubernetes
import pytest
import pytest_asyncio
import requests
from pytest_operator.plugin import OpsTest

from charm import CREATED_BY_LABEL

INGRESS_APP_NAME = "ingress"
ANY_APP_NAME = "any"
NEW_HOSTNAME = "any.other"
NEW_INGRESS = "any-other-ingress"
NEW_PORT = 18080


@pytest_asyncio.fixture(scope="module")
async def build_and_deploy(ops_test: OpsTest, run_action):
    """build and deploy nginx-ingress-integrator charm.

    Also deploy and relate an any-charm application for test purposes.

    Returns: None.
    """
    ingress_lib = Path("lib/charms/nginx_ingress_integrator/v0/ingress.py").read_text()
    any_charm_script = Path("tests/integration/any_charm.py").read_text()
    any_charm_src_overwrite = {
        "ingress.py": ingress_lib,
        "any_charm.py": any_charm_script,
    }

    async def build_and_deploy_ingress():
        charm = await ops_test.build_charm(".")
        return await ops_test.model.deploy(
            str(charm), application_name="ingress", series="focal", trust=True
        )

    await asyncio.gather(
        ops_test.model.deploy(
            "any-charm",
            application_name="any",
            channel="beta",
            config={"src-overwrite": json.dumps(any_charm_src_overwrite)},
        ),
        build_and_deploy_ingress(),
    )
    await ops_test.model.wait_for_idle()
    await run_action(ANY_APP_NAME, "rpc", method="start_server")
    await ops_test.model.add_relation(ANY_APP_NAME, f"{INGRESS_APP_NAME}:ingress")
    await ops_test.model.wait_for_idle()


@pytest.mark.usefixtures("build_and_deploy")
async def test_delete_unused_ingresses(ops_test: OpsTest):
    """
    arrange: given charm has been built, deployed and related to a dependent application
    act: when the service-hostname is changed and when is back to previous value
    assert: then the workload status is active and the unused ingress is deleted
    """
    kubernetes.config.load_kube_config()
    api_networking = kubernetes.client.NetworkingV1Api()
    model_name = ops_test.model.name
    created_by_label = f"{CREATED_BY_LABEL}ingress"

    def compare_svc_hostnames(expected: List[str]) -> bool:
        all_ingresses = api_networking.list_namespaced_ingress(
            namespace=model_name, label_selector=created_by_label
        )
        return expected == [ingress.spec.rules[0].host for ingress in all_ingresses.items]

    assert compare_svc_hostnames(["any"])
    await ops_test.juju("config", INGRESS_APP_NAME, "service-hostname=new-name")
    await ops_test.model.wait_for_idle(status="active")
    assert compare_svc_hostnames(["new-name"])
    await ops_test.juju("config", INGRESS_APP_NAME, "service-hostname=")
    await ops_test.model.wait_for_idle(status="active")
    assert compare_svc_hostnames(["any"])


@pytest.mark.usefixtures("build_and_deploy")
async def test_delete_unused_services(ops_test: OpsTest):
    """
    arrange: given charm has been built, deployed and related to a dependent application
    act: when the service-name is changed and when is back to previous value
    assert: then the workload status is active and the unused service is deleted
    """
    kubernetes.config.load_kube_config()
    api_core = kubernetes.client.CoreV1Api()
    model_name = ops_test.model.name
    created_by_label = f"{CREATED_BY_LABEL}ingress"

    def compare_svc_names(expected: List[str]) -> bool:
        all_services = api_core.list_namespaced_service(
            namespace=model_name, label_selector=created_by_label
        )
        return expected == [item.metadata.name for item in all_services.items]

    assert compare_svc_names(["any-service"])
    await ops_test.juju("config", INGRESS_APP_NAME, "service-name=new-name")
    await ops_test.model.wait_for_idle(status="active")
    assert compare_svc_names(["new-name-service"])
    await ops_test.juju("config", INGRESS_APP_NAME, "service-name=")
    await ops_test.model.wait_for_idle(status="active")
    assert compare_svc_names(["any-service"])


@pytest_asyncio.fixture(scope="module")
async def setup_new_hostname_and_port(ops_test, build_and_deploy, run_action, wait_for_ingress):
    """Update the service-hostname to NEW_HOSTNAME and service-port to NEW_PORT via any-charm.

    Returns: None.
    """
    rpc_return = await run_action(
        ANY_APP_NAME, "rpc", method="start_server", kwargs=json.dumps({"port": NEW_PORT})
    )
    assert rpc_return["return-code"] == 0 and json.loads(rpc_return["return"]) == NEW_PORT
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


@pytest.mark.usefixtures("build_and_deploy")
async def test_ingress_connectivity():
    """
    arrange: given charm has been built and deployed.
    act: access ingress IP address with correct host name in HTTP headers.
    assert: HTTP request should be forwarded to the application.
    """
    response = requests.get("http://127.0.0.1/ok", headers={"Host": "any"}, timeout=5)
    assert response.text == "ok"
    assert response.status_code == 200
    assert (
        requests.get("http://127.0.0.1/ok", headers={"Host": NEW_HOSTNAME}, timeout=5).status_code
        == 404
    )


@pytest.mark.usefixtures("build_and_deploy", "setup_new_hostname_and_port")
async def test_update_host_and_port_via_relation(run_action, wait_for_ingress):
    """
    arrange: given charm has been built and deployed.
    act: update service-hostname and service-port via ingress library.
    assert: kubernetes ingress should be updated to accommodate the relation data update.
    """
    response = requests.get("http://127.0.0.1/ok", headers={"Host": NEW_HOSTNAME})
    assert response.text == "ok"
    assert response.status_code == 200


@pytest.mark.usefixtures("build_and_deploy", "setup_new_hostname_and_port")
async def test_owasp_modsecurity_crs_relation(ops_test: OpsTest, run_action):
    """
    arrange: given charm has been built and deployed.
    act: toggle modsecurity option via ingress library.
    assert: modsecurity should be enabled and ingress should reject malicious requests.
    """
    kubernetes.config.load_kube_config()
    kube = kubernetes.client.NetworkingV1Api()
    model_name = ops_test.model.name

    def get_ingress_annotation():
        return kube.read_namespaced_ingress(NEW_INGRESS, namespace=model_name).metadata.annotations

    ingress_annotations = get_ingress_annotation()
    assert "nginx.ingress.kubernetes.io/enable-modsecurity" not in ingress_annotations
    assert "nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs" not in ingress_annotations
    assert "nginx.ingress.kubernetes.io/modsecurity-snippet" not in ingress_annotations

    await run_action(
        ANY_APP_NAME,
        "rpc",
        method="update_ingress",
        kwargs=json.dumps(
            {
                "ingress_config": {
                    "service-hostname": NEW_HOSTNAME,
                    "service-port": NEW_PORT,
                    "owasp-modsecurity-crs": True,
                }
            }
        ),
    )
    await ops_test.model.wait_for_idle(status="active")
    await ops_test.model.block_until(
        lambda: "nginx.ingress.kubernetes.io/enable-modsecurity" in get_ingress_annotation(),
        wait_period=5,
        timeout=300,
    )

    assert (
        requests.get(
            "http://127.0.0.1/?search=../../passwords", headers={"Host": NEW_HOSTNAME}, timeout=5
        ).status_code
        == 403
    )
    ingress_annotations = get_ingress_annotation()
    assert ingress_annotations["nginx.ingress.kubernetes.io/enable-modsecurity"] == "true"
    assert (
        ingress_annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"] == "true"
    )
    assert ingress_annotations["nginx.ingress.kubernetes.io/modsecurity-snippet"]
