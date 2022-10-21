# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest_asyncio
import yaml
from ops.model import ActiveStatus
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
        charm, application_name=app_name, series="focal"
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
    await ops_test.model.wait_for_idle(status=ActiveStatus.name)

    yield application
