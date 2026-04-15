# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Integration test relation file."""

import json
import time
import typing
from pathlib import Path

import jubilant
import pytest
import requests

INGRESS_APP_NAME = "ingress"
ANY_APP_NAME = "any"
NEW_HOSTNAME = "any.other"


def gen_src_overwrite(
    service_hostname: str = "any",
    service_name: str = "any",
    service_port: int = 8080,
    additional_hostnames: typing.Optional[str] = None,
) -> str:
    """Generate the src-overwrite config value for testing nginx-route relation.

    Args:
        service_hostname: Ingress service hostname.
        service_name: Ingress service name.
        service_port: Ingress service port
        additional_hostnames: Ingress additional hostnames

    Returns:
        written src-overwrite variable.
    """
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
    """Requests get, but will retry when the response status code is not 200.

    Args:
        url: URL to request.
        host_header: Host header for the request.
        retry_timeout: time to retry the request if the request fails.

    Returns:
        An HTTP response for the request.
    """
    time_start = time.time()
    while True:
        response = requests.get(url, headers={"Host": host_header}, timeout=5)
        if response.status_code == 200 or time.time() - time_start > retry_timeout:
            return response
        time.sleep(1)


@pytest.fixture(scope="module")
def build_and_deploy(juju: jubilant.Juju, deploy_any_charm, run_action, build_and_deploy_ingress):
    """Build and deploy nginx-ingress-integrator charm.

    Also deploy and relate an any-charm application for test purposes.

    Returns: None.
    """
    deploy_any_charm(gen_src_overwrite())
    build_and_deploy_ingress()
    juju.wait(jubilant.all_agents_idle)
    run_action(ANY_APP_NAME, "rpc", method="start_server")
    relation_name = f"{INGRESS_APP_NAME}:nginx-route"
    juju.integrate(f"{ANY_APP_NAME}:nginx-route", relation_name)
    juju.wait(jubilant.all_agents_idle)


@pytest.mark.usefixtures("build_and_deploy")
def test_ingress_connectivity():
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
def test_ingress_connectivity_different_backend(juju: jubilant.Juju):
    """
    arrange: given charm has been built and deployed.
    act: change the backend protocol.
    assert: HTTP request should be forwarded to the application via GRPC
        resulting in HTTP status code 502 Bad Gateway.
    """
    # First check if is OK
    response = requests_get("http://127.0.0.1/ok", host_header="any")
    assert response.text == "ok"
    assert response.status_code == 200
    # Then change the config and check if there is an error
    juju.config(INGRESS_APP_NAME, {"backend-protocol": "GRPC"})
    juju.wait(jubilant.all_active)
    response = requests_get("http://127.0.0.1/ok", host_header="any")
    assert response.status_code == 502
    # Undo the change and check again
    juju.config(INGRESS_APP_NAME, {"backend-protocol": "HTTP"})
    juju.wait(jubilant.all_active)
    response = requests_get("http://127.0.0.1/ok", host_header="any")
    assert response.text == "ok"
    assert response.status_code == 200


@pytest.mark.usefixtures("build_and_deploy")
def test_ingress_connectivity_invalid_backend(juju: jubilant.Juju):
    """
    arrange: given charm has been built and deployed.
    act: change the backend protocol.
    assert: unit status is blocked.
    """
    # First check if is OK
    response = requests_get("http://127.0.0.1/ok", host_header="any")
    assert response.text == "ok"
    assert response.status_code == 200
    # Then change the config and check if there is an error
    juju.config(INGRESS_APP_NAME, {"backend-protocol": "FAKE"})
    juju.wait(jubilant.all_agents_idle)
    status = juju.status()
    unit_status = status.apps[INGRESS_APP_NAME].units[f"{INGRESS_APP_NAME}/0"]
    assert unit_status.workload_status.current == "blocked"
    assert "invalid backend protocol" in unit_status.workload_status.message
    # Undo the change and check again
    juju.config(INGRESS_APP_NAME, {"backend-protocol": "HTTP"})
    juju.wait(jubilant.all_active)
    response = requests_get("http://127.0.0.1/ok", host_header="any")
    assert response.text == "ok"
    assert response.status_code == 200


@pytest.fixture(name="set_service_hostname")
def set_service_hostname_fixture(juju: jubilant.Juju):
    """A fixture to set service-hostname to NEW_HOSTNAME in the any-charm nginx-route relation."""
    juju.config(ANY_APP_NAME, {"src-overwrite": gen_src_overwrite(service_hostname=NEW_HOSTNAME)})
    juju.wait(jubilant.all_active)
    yield
    juju.config(ANY_APP_NAME, {"src-overwrite": gen_src_overwrite()})
    juju.wait(jubilant.all_active)


@pytest.mark.usefixtures("build_and_deploy", "set_service_hostname")
def test_update_service_hostname():
    """
    arrange: given charm has been built and deployed.
    act: update the service-hostname option in any-charm.
    assert: HTTP request with the service-hostname value as the host header should be forwarded
        to the application correctly.
    """
    response = requests_get("http://127.0.0.1/ok", host_header=NEW_HOSTNAME)
    assert response.text == "ok"
    assert response.status_code == 200


@pytest.fixture(name="set_additional_hosts")
def set_additional_hosts_fixture(juju: jubilant.Juju, run_action):
    """A fixture to set additional-hosts to NEW_HOSTNAME in the any-charm nginx-route relation."""
    juju.config(
        ANY_APP_NAME, {"src-overwrite": gen_src_overwrite(additional_hostnames=NEW_HOSTNAME)}
    )
    juju.wait(jubilant.all_active)
    yield
    juju.config(ANY_APP_NAME, {"src-overwrite": gen_src_overwrite()})
    juju.wait(jubilant.all_active)
    action_result = run_action(ANY_APP_NAME, "get-relation-data")
    relation_data = json.loads(action_result["relation-data"])[0]
    assert "additional-hostnames" not in relation_data["application_data"]["any"]


@pytest.mark.usefixtures("build_and_deploy", "set_additional_hosts")
def test_update_additional_hosts(run_action):
    """
    arrange: given charm has been built and deployed,
    act: update the additional-hostnames option in the nginx-route relation using any-charm.
    assert: HTTP request with the additional-hostnames value as the host header should be
        forwarded to the application correctly. And the additional-hostnames should exist
        in the nginx-route relation data.
    """
    response = requests_get("http://127.0.0.1/ok", host_header=NEW_HOSTNAME)
    assert response.text == "ok"
    assert response.status_code == 200
    action_result = run_action(ANY_APP_NAME, "get-relation-data")
    relation_data = json.loads(action_result["relation-data"])[0]
    assert "additional-hostnames" in relation_data["application_data"]["any"]


@pytest.mark.usefixtures("build_and_deploy")
def test_missing_field(juju: jubilant.Juju, run_action):
    """
    arrange: given charm has been built and deployed.
    act: update the nginx-route relation data with service-name missing.
    assert: Nginx ingress integrator charm should enter blocked status.
    """
    juju.config(ANY_APP_NAME, {"src-overwrite": gen_src_overwrite()})
    run_action(
        ANY_APP_NAME,
        "rpc",
        method="delete_nginx_route_relation_data",
        kwargs=json.dumps({"field": "service-name"}),
    )
    juju.wait(jubilant.all_agents_idle)
    status = juju.status()
    unit_status = status.apps[INGRESS_APP_NAME].units[f"{INGRESS_APP_NAME}/0"]
    assert unit_status.workload_status.current == "blocked"
    assert unit_status.workload_status.message == "Missing fields for nginx-route: service-name"
