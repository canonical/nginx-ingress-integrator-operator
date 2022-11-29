import asyncio
import json
from pathlib import Path

import kubernetes
import requests
from pytest_operator.plugin import OpsTest

INGRESS_APP_NAME = "ingress"
ANY_APP_NAME = "any"
NEW_HOSTNAME = "any.other"
NEW_PORT = 18080


async def test_build_and_deploy(ops_test: OpsTest, run_action):
    """
    arrange: no arrange.
    act: build and deploy nginx-ingress-integrator charm, also deploy and relate an any-charm
        application for test purposes.
    assert: all application should be active.
    """
    ingress_lib = Path("lib/charms/nginx_ingress_integrator/v0/ingress.py").read_text()
    any_charm_script = Path("tests/integration/any_charm.py").read_text()
    any_charm_src_overwrite = {
        "ingress.py": ingress_lib,
        "any_charm.py": any_charm_script,
    }

    async def build_and_deploy():
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
        build_and_deploy(),
    )
    await ops_test.model.wait_for_idle()
    await run_action(ANY_APP_NAME, "rpc", method="start_server")
    await ops_test.model.add_relation(ANY_APP_NAME, f"{INGRESS_APP_NAME}:ingress")
    await ops_test.model.wait_for_idle()


async def test_ingress_connectivity():
    """
    arrange: given charm has been built and deployed.
    act: access ingress IP address with correct host name in HTTP headers.
    assert: HTTP request should be forwarded to the application.
    """
    response = requests.get("http://127.0.0.1/ok", headers={"Host": "any"}, timeout=5)
    assert response.text == "ok"
    assert response.status_code == 200


async def test_update_host_and_port_via_relation(ops_test, run_action):
    """
    arrange: given charm has been built and deployed.
    act: update service-hostname and service-port via ingress library.
    assert: kubernetes ingress should be updated to accommodate the relation data update.
    """
    assert (
        requests.get("http://127.0.0.1/ok", headers={"Host": NEW_HOSTNAME}, timeout=5).status_code
        == 404
    )

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

    response = requests.get("http://127.0.0.1/ok", headers={"Host": NEW_HOSTNAME})
    assert response.text == "ok"
    assert response.status_code == 200


async def test_owasp_modsecurity_crs_relation(ops_test: OpsTest, run_action):
    """
    arrange: given charm has been built and deployed.
    act: toggle modsecurity option via ingress library.
    assert: modsecurity should be enabled and ingress should reject malicious requests.
    """
    kubernetes.config.load_kube_config()
    kube = kubernetes.client.NetworkingV1Api()
    ingress_annotations = kube.read_namespaced_ingress(
        "any-other-ingress", namespace=ops_test.model.name
    ).metadata.annotations
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

    assert (
        requests.get(
            "http://127.0.0.1/?search=../../passwords", headers={"Host": NEW_HOSTNAME}, timeout=5
        ).status_code
        == 403
    )

    ingress_annotations = kube.read_namespaced_ingress(
        "any-other-ingress", namespace=ops_test.model.name
    ).metadata.annotations
    assert ingress_annotations["nginx.ingress.kubernetes.io/enable-modsecurity"] == "true"
    assert (
        ingress_annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"] == "true"
    )
    assert ingress_annotations["nginx.ingress.kubernetes.io/modsecurity-snippet"]
