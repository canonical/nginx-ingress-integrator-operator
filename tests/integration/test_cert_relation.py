# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=redefined-outer-name,unused-argument,duplicate-code

"""Integration test relation file."""

import logging

import pytest
from juju.model import Model
from ops.model import ActiveStatus
from pytest_operator.plugin import OpsTest

LOGGER = logging.getLogger(__name__)

# Mypy can't recognize the name as a string type, so we should skip the type check.
ACTIVE_STATUS_NAME = ActiveStatus.name
PROVIDER_CHARM_DIR = "tests/integration/provider_charm"
TLS_CERTIFICATES_PROVIDER_APP_NAME = "tls-certificates-provider"


@pytest.mark.usefixtures("build_and_deploy")
async def test_deploy_cert_provider(model: Model, ops_test: OpsTest):
    """
    arrange: given charm has been built, deployed and integrated with a dependent application.
    act: deploy the dummy certificate provider charm.
    assert: the deployment is successfully blocked due to a lack of integration.
    """
    provider_charm = await ops_test.build_charm(f"{PROVIDER_CHARM_DIR}/")
    await model.deploy(
        provider_charm,
        application_name=TLS_CERTIFICATES_PROVIDER_APP_NAME,
        series="jammy",
    )

    await model.wait_for_idle(
        apps=[TLS_CERTIFICATES_PROVIDER_APP_NAME],
        status="blocked",
        timeout=1000,
    )


async def test_given_charms_deployed_when_relate_then_status_is_active(
    model: Model, ops_test: OpsTest
):
    """
    arrange: dummy certificate charm has been deployed.
    act: integate the dummy certificate provider charm to the given charm.
    assert: the integration is successful.
    """
    await model.add_relation(TLS_CERTIFICATES_PROVIDER_APP_NAME, "ingress:certificates")

    await model.wait_for_idle(
        apps=["ingress", TLS_CERTIFICATES_PROVIDER_APP_NAME],
        status="active",
        timeout=1000,
    )


async def test_given_charms_deployed_when_relate_then_requirer_received_certs(
    model: Model, ops_test: OpsTest
):
    """
    arrange: given charm has been built, deployed and related to a certificate provider.
    act: get the current certificates provided.
    assert: the given charm has been provided a certificate successfully.
    """
    requirer_unit = model.units["ingress/0"]

    action = await requirer_unit.run_action(action_name="get-certificate")

    action_output = await model.get_action_output(action_uuid=action.entity_id, wait=60)
    assert action_output["return-code"] == 0
    assert "ca" in action_output and action_output["ca"] is not None
    assert "certificate" in action_output and action_output["certificate"] is not None
    assert "chain" in action_output and action_output["chain"] is not None


async def test_given_additional_requirer_charm_deployed_when_relate_then_requirer_received_certs(
    model: Model, ops_test: OpsTest
):
    """
    arrange: given charm has been built, deployed and integrated with a dependent application.
    act: deploy another instance of the given charm.
    assert: the process of deployment, integration and certificate provision is successful.
    """
    new_requirer_app_name = "ingress2"
    charm = await ops_test.build_charm(".")
    await model.deploy(
        str(charm), application_name=new_requirer_app_name, series="focal", trust=True
    )
    await model.add_relation(
        TLS_CERTIFICATES_PROVIDER_APP_NAME, f"{new_requirer_app_name}:certificates"
    )
    await model.wait_for_idle(
        apps=[
            TLS_CERTIFICATES_PROVIDER_APP_NAME,
            new_requirer_app_name,
        ],
        status="active",
        timeout=1000,
    )
    requirer_unit = model.units[f"{new_requirer_app_name}/0"]

    action = await requirer_unit.run_action(action_name="get-certificate")

    action_output = await model.get_action_output(action_uuid=action.entity_id, wait=60)
    assert action_output["return-code"] == 0
    assert "ca" in action_output and action_output["ca"] is not None
    assert "certificate" in action_output and action_output["certificate"] is not None
    assert "chain" in action_output and action_output["chain"] is not None


async def test_given_enough_time_passed_then_certificate_expired(model: Model, ops_test: OpsTest):
    """
    arrange: given charm has been built, deployed and related to a certificate provider.
    act: wait until the certificate expires.
    assert: the certificate expires and the given charm waits for a new certificate.
    """
    await model.wait_for_idle(
        apps=[
            "ingress",
        ],
        status="maintenance",
        timeout=1000,
        idle_period=0,
    )
    requirer_unit = model.units["ingress/0"]

    assert requirer_unit.workload_status_message == "Waiting for new certificate"
