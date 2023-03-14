# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test relation file."""

import asyncio
import json
import time
import typing
from pathlib import Path

import pytest
import pytest_asyncio
import requests
from juju.model import Model
from pytest_operator.plugin import OpsTest

INGRESS_APP_NAME = "ingress"
ANY_APP_NAME = "any"


def gen_src_overwrite(
    service_hostname: str = "any",
    service_name: str = "any",
    service_port: int = 8080,
    additional_hostnames: typing.Optional[str] = None,
) -> str:
    """Generate the src-overwrite config value for testing nginx-route relation."""
    nginx_route_lib_path = "lib/charms/nginx_ingress_integrator/v0/nginx_route.py"
    nginx_route_lib = Path(nginx_route_lib_path).read_text(encoding="utf8")
    any_charm_script = Path("tests/integration/any_charm_nginx_route.py").read_text(
        encoding="utf8"
    )
    nginx_route_config = {
        "service_hostname": service_hostname,
        "service_name": service_name,
        "service_port": service_port,
    }
    if additional_hostnames:
        nginx_route_config["additional_hostnames"] = additional_hostnames
    any_charm_src_overwrite = {
        "any_charm.py": any_charm_script,
        "nginx_route.py": nginx_route_lib,
        "nginx_route_config.json": json.dumps(nginx_route_config),
    }
    return json.dumps(any_charm_src_overwrite)


def requests_get(url: str, host_header: str, retry_timeout: int = 120) -> requests.Response:
    """Requests get, but will retry when the response status code is not 200."""
    time_start = time.time()
    while True:
        response = requests.get(url, headers={"Host": host_header}, timeout=5)
        if response.status_code == 200 or time.time() - time_start > retry_timeout:
            return response
        time.sleep(1)


@pytest_asyncio.fixture(scope="module")
async def build_and_deploy(model: Model, deploy_any_charm, run_action, build_and_deploy_ingress):
    """build and deploy nginx-ingress-integrator charm.

    Also deploy and relate an any-charm application for test purposes.

    Returns: None.
    """
    await asyncio.gather(
        deploy_any_charm(gen_src_overwrite()),
        build_and_deploy_ingress(),
    )
    await model.wait_for_idle()
    await run_action(ANY_APP_NAME, "rpc", method="start_server")
    relation_name = f"{INGRESS_APP_NAME}:nginx-route"
    await model.add_relation(f"{ANY_APP_NAME}:nginx-route", relation_name)
    await model.wait_for_idle()


@pytest.mark.usefixtures("build_and_deploy")
async def test_ingress_connectivity():
    """
    arrange: given charm has been built and deployed.
    act: access ingress IP address with correct host name in HTTP headers.
    assert: HTTP request should be forwarded to the application, while a HTTP request without the
        correct Host header should return with a response of 404 NOT FOUND.
    """
    response = requests_get("http://127.0.0.1/ok", host_header="any")

    assert response.text == "ok"
    assert response.status_code == 200
    assert (
        requests_get("http://127.0.0.1/ok", host_header="any.other", retry_timeout=0).status_code
        == 404
    )


@pytest.mark.usefixtures("build_and_deploy")
async def test_update_service_hostname(ops_test: OpsTest):
    """
    arrange: given charm has been built and deployed.
    act: update the service-hostname option in any-charm.
    assert: HTTP request with the service-hostname value as the host header should be forwarded
        to the application correctly.
    """
    new_hostname = "any.other"
    assert ops_test.model
    await ops_test.model.applications[ANY_APP_NAME].set_config(
        {"src-overwrite": gen_src_overwrite(service_hostname=new_hostname)}
    )
    await ops_test.model.wait_for_idle(status="active")

    response = requests_get("http://127.0.0.1/ok", host_header=new_hostname)
    assert response.text == "ok"
    assert response.status_code == 200

    await ops_test.model.applications[ANY_APP_NAME].set_config(
        {"src-overwrite": gen_src_overwrite()}
    )
    await ops_test.model.wait_for_idle(status="active")


@pytest.mark.usefixtures("build_and_deploy")
async def test_update_additional_hosts(ops_test: OpsTest, run_action):
    """
    arrange: given charm has been built and deployed,
    act: update the additional-hostnames option in the nginx-route relation using any-charm.
    assert: HTTP request with the additional-hostnames value as the host header should be
        forwarded to the application correctly. And the additional-hostnames should exist
        in the nginx-route relation data.
    """

    async def get_relation_data():
        action_result = await run_action(ANY_APP_NAME, "get-relation-data")
        relation_data = json.loads(action_result["relation-data"])[0]
        return relation_data["application_data"]["any"]

    new_hostname = "any.new"
    assert ops_test.model
    await ops_test.model.applications[ANY_APP_NAME].set_config(
        {"src-overwrite": gen_src_overwrite(additional_hostnames=new_hostname)}
    )

    await ops_test.model.wait_for_idle(status="active")
    response = requests_get("http://127.0.0.1/ok", host_header=new_hostname)
    assert response.text == "ok"
    assert response.status_code == 200
    assert "additional-hostnames" in await get_relation_data()

    await ops_test.model.applications[ANY_APP_NAME].set_config(
        {"src-overwrite": gen_src_overwrite()}
    )

    await ops_test.model.wait_for_idle(status="active")
    assert "additional-hostnames" not in await get_relation_data()


@pytest.mark.usefixtures("build_and_deploy")
async def test_missing_field(ops_test: OpsTest, run_action):
    """
    arrange: given charm has been built and deployed,
    act: update the nginx-route relation data with service-name missing.
    assert: Nginx ingress integrator charm should enter blocked status.
    """

    assert ops_test.model
    await ops_test.model.applications[ANY_APP_NAME].set_config(
        {"src-overwrite": gen_src_overwrite()}
    )
    await run_action(
        ANY_APP_NAME,
        "rpc",
        method="delete_nginx_route_relation_data",
        kwargs=json.dumps({"field": "service-name"}),
    )
    await ops_test.model.wait_for_idle()
    unit = ops_test.model.applications[INGRESS_APP_NAME].units[0]
    assert unit.workload_status == "blocked"
    assert unit.workload_status_message == "Missing fields for nginx-route: service-name"
