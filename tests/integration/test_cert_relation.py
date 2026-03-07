# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test relation file."""

import json
import logging
import time
import typing
from pathlib import Path

import jubilant
import pytest

LOGGER = logging.getLogger(__name__)

TLS_CERTIFICATES_PROVIDER_APP_NAME = "self-signed-certificates"
SELF_SIGNED_CERTIFICATES_CHARM_NAME = "self-signed-certificates"
INGRESS_APP_NAME = "ingress"
ANY_APP_NAME = "any"
ANY_APP_NAME_2 = "any2"
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


@pytest.fixture(scope="module")
def build_and_deploy(
    juju: jubilant.Juju,
    deploy_any_charm,
    run_action,
    build_and_deploy_ingress,
):
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
    juju.deploy(
        SELF_SIGNED_CERTIFICATES_CHARM_NAME,
        TLS_CERTIFICATES_PROVIDER_APP_NAME,
        channel="1/stable",
    )
    juju.wait(
        lambda s: jubilant.all_active(s, TLS_CERTIFICATES_PROVIDER_APP_NAME),
        timeout=1000,
    )


@pytest.mark.usefixtures("build_and_deploy")
def test_given_charms_deployed_when_relate_then_status_is_active(juju: jubilant.Juju):
    """
    arrange: sample certificate charm has been deployed.
    act: integrate the sample certificate provider charm to the given charm.
    assert: the integration is successful.
    """
    juju.integrate(TLS_CERTIFICATES_PROVIDER_APP_NAME, "ingress:certificates")
    juju.wait(
        lambda s: jubilant.all_active(s, INGRESS_APP_NAME, TLS_CERTIFICATES_PROVIDER_APP_NAME),
        timeout=1000,
    )


@pytest.mark.usefixtures("build_and_deploy")
def test_given_charms_deployed_when_relate_then_requirer_received_certs(juju: jubilant.Juju):
    """
    arrange: given charm has been built, deployed and related to a certificate provider.
    act: get the current certificates provided.
    assert: the given charm has been provided a certificate successfully.
    """
    task = juju.run("ingress/0", "get-certificate", params={"hostname": "any"})
    assert task.results.get("ca-any") is not None
    assert task.results.get("certificate-any") is not None
    assert task.results.get("chain-any") is not None


@pytest.mark.usefixtures("build_and_deploy")
def test_given_additional_requirer_charm_deployed_when_relate_then_requirer_received_certs(
    juju: jubilant.Juju,
    run_action,
    build_and_deploy_ingress,
):
    """
    arrange: given charm has been built, deployed and integrated with a dependent application.
    act: deploy another instance of the given charm.
    assert: the process of deployment, integration and certificate provision is successful.
    """
    new_requirer_app_name = "ingress2"
    build_and_deploy_ingress(application_name=new_requirer_app_name)
    juju.deploy(
        "any-charm",
        ANY_APP_NAME_2,
        channel="beta",
        config={"src-overwrite": gen_src_overwrite()},
    )
    juju.wait(jubilant.all_agents_idle)
    run_action(ANY_APP_NAME_2, "rpc", method="start_server")
    relation_name = f"{new_requirer_app_name}:nginx-route"
    juju.integrate(f"{ANY_APP_NAME_2}:nginx-route", relation_name)
    juju.wait(jubilant.all_agents_idle)

    juju.integrate(
        TLS_CERTIFICATES_PROVIDER_APP_NAME, f"{new_requirer_app_name}:certificates"
    )
    juju.wait(
        lambda s: jubilant.all_active(
            s, TLS_CERTIFICATES_PROVIDER_APP_NAME, new_requirer_app_name
        ),
        timeout=1000,
    )

    t0 = time.time()
    timeout = 600
    while time.time() - t0 < timeout:
        try:
            task = juju.run(
                f"{new_requirer_app_name}/0",
                "get-certificate",
                params={"hostname": "any"},
            )
            keys = ["ca-any", "certificate-any", "chain-any"]
            if all(task.results.get(key) for key in keys):
                LOGGER.info("Certificate received")
                return
        except jubilant.TaskError:
            pass
        LOGGER.info("Waiting for certificate")
        time.sleep(5)
    raise TimeoutError("Timed out waiting for certificate")
