# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""General configuration module for integration tests."""

import time
from pathlib import Path

import jubilant
import kubernetes
import pytest
import pytest_jubilant
import yaml
from pytest import Config, fixture

ANY_APP_NAME = "any"
INGRESS_APP_NAME = "ingress"
NEW_HOSTNAME = "any.other"
NEW_INGRESS = "any-other-ingress"
NEW_PORT = 18080


@fixture(scope="module", name="metadata")
def metadata_fixture():
    """Provide charm metadata."""
    yield yaml.safe_load(Path("./charmcraft.yaml").read_text(encoding="utf8"))


@fixture(scope="module")
def app_name(metadata):
    """Provide app name from the metadata."""
    yield metadata["name"]


@fixture(scope="module", autouse=True)
def model_arch(juju: jubilant.Juju, pytestconfig: Config) -> None:
    """Set model architecture constraint if provided."""
    model_arch = pytestconfig.getoption("--model-arch")
    if model_arch:
        juju.model_constraints({"arch": model_arch})


@fixture(scope="module")
def run_action(juju: jubilant.Juju):
    """Create a function to run an action and return its results."""

    def _run_action(application_name, action_name, **params):
        """Run a juju action.

        Args:
            application_name: Name of the Juju application.
            action_name: Name of the action to execute.
            params: Extra parameters for the action.

        Returns:
            The results of the action.
        """
        task = juju.run(
            f"{application_name}/0",
            action_name,
            params=params if params else None,
        )
        return task.results

    return _run_action


@fixture(scope="module")
def wait_for_ingress(juju: jubilant.Juju):
    """Create a function that waits until an ingress resource with a given name exists."""
    kubernetes.config.load_kube_config()
    kube = kubernetes.client.NetworkingV1Api()

    def _wait_for_ingress(ingress_name):
        """Wait for the Ingress to be configured.

        Args:
            ingress_name: Name of the Ingress.
        """
        deadline = time.time() + 10 * 60
        while time.time() < deadline:
            names = [
                ingress.metadata.name for ingress in kube.list_namespaced_ingress(juju.model).items
            ]
            if ingress_name in names:
                return
            time.sleep(5)
        raise TimeoutError(f"Timed out waiting for ingress {ingress_name!r}")

    return _wait_for_ingress


@fixture(scope="module", name="get_ingress_annotation")
def get_ingress_annotation_fixture(juju: jubilant.Juju):
    """Create a function that retrieves all annotations from an ingress by its name."""
    kubernetes.config.load_kube_config()
    kube = kubernetes.client.NetworkingV1Api()

    def _get_ingress_annotation(ingress_name: str):
        """Get the annotations from an Ingress.

        Args:
            ingress_name: Name of the Ingress.

        Returns:
            The annotations from the requested Ingress.
        """
        return kube.read_namespaced_ingress(
            ingress_name, namespace=juju.model
        ).metadata.annotations

    return _get_ingress_annotation


@fixture(scope="module")
def wait_ingress_annotation(get_ingress_annotation):
    """Create a function that waits until a certain annotation exists on an ingress."""

    def _wait_ingress_annotation(ingress_name: str, annotation_name: str):
        """Wait until the ingress annotations are applied.

        Args:
            ingress_name: Name of the ingress.
            annotation_name: Name of the ingress' annotation.
        """
        deadline = time.time() + 300
        while time.time() < deadline:
            if annotation_name in get_ingress_annotation(ingress_name):
                return
            time.sleep(5)
        raise TimeoutError(
            f"Timed out waiting for annotation {annotation_name!r} on ingress {ingress_name!r}"
        )

    return _wait_ingress_annotation


@fixture(scope="module")
def build_and_deploy_ingress(juju: jubilant.Juju, pytestconfig: pytest.Config):
    """Create a function to build the nginx ingress integrator charm then deploy it."""

    def _build_and_deploy_ingress(application_name: str = "ingress"):
        """Build and deploy the Ingress charm.

        Args:
            application_name: Name to give the deployed application.
        """
        charm = pytestconfig.getoption("--charm-file")
        if not charm:
            charm = pytest_jubilant.pack()
        juju.deploy(str(charm), application_name, base="ubuntu@22.04", trust=True)

    return _build_and_deploy_ingress


@fixture(scope="module")
def deploy_any_charm(juju: jubilant.Juju):
    """Create a function to deploy any-charm.

    The function accepts a string as the initial src-overwrite configuration.
    """

    def _deploy_any_charm(src_overwrite):
        """Deploy the any-charm for testing.

        Args:
            src_overwrite: Files to overwrite for testing purposes.
        """
        juju.deploy(
            "any-charm",
            "any",
            channel="beta",
            config={"python-packages": "pydantic<2.0", "src-overwrite": src_overwrite},
        )

    return _deploy_any_charm
