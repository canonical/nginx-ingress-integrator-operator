import json
import subprocess  # nosec B404
from pathlib import Path
from textwrap import dedent

import kubernetes
import pytest
from ops.model import ActiveStatus
from pytest_operator.plugin import OpsTest

async def build_and_deploy(ops_test: OpsTest, app_name: str):
    """Build ingress charm used for integration testing.

    Builds the charm and deploys it and a charm that depends on it.
    """
    # Build and deploy ingress
    charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(
        str(charm), application_name=app_name, series="focal", trust=True
    )
    await ops_test.model.wait_for_idle(status=ActiveStatus.name)


@pytest.mark.usefixtures("app")
async def test_owasp_modsecurity_crs_relation(ops_test: OpsTest, app_name: str, tmp_path: Path):
    """
    arrange: given charm has been built and deployed
    act: relate the ingress integrator with any-charm and use any-charm to toggle modsecurity
        option through relation via ingress lib.
    assert: modsecurity annotations should be attached and detached from the kubernetes ingress
        resource according to the modsecurity option.
    """
    any_charm_tmp_path = tmp_path / "any-charm"
    if not any_charm_tmp_path.exists():
        subprocess.run(
            ["git", "clone", "https://github.com/weiiwang01/any-charm.git", any_charm_tmp_path]
        )  # nosec

    any_charm = await ops_test.build_charm(any_charm_tmp_path)
    ingress_lib = Path("lib/charms/nginx_ingress_integrator/v0/ingress.py").read_text()
    any_charm_src_overwrite = {
        "ingress.py": ingress_lib,
        "any_charm.py": dedent(
            """\
        from ingress import IngressRequires
        from any_charm_base import AnyCharmBase
        class AnyCharm(AnyCharmBase):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.ingress = IngressRequires(
                    self, 
                    {
                        "service-hostname": "any",
                        "service-name": self.app.name,
                        "service-port": 80,
                        "owasp-modsecurity-crs": True
                    }
                )
            def update_ingress(self, ingress_config):
                self.ingress.update_config(ingress_config)
        """
        ),
    }
    await ops_test.model.deploy(
        str(any_charm),
        application_name="any",
        series="focal",
        config={"src-overwrite": json.dumps(any_charm_src_overwrite)},
    )
    await ops_test.model.add_relation("any", f"{app_name}:ingress")
    await ops_test.model.wait_for_idle(status=ActiveStatus.name)

    kubernetes.config.load_kube_config()
    kube = kubernetes.client.NetworkingV1Api()
    ingress_annotations = kube.read_namespaced_ingress(
        "any-ingress", namespace=ops_test.model.name
    ).metadata.annotations
    assert ingress_annotations["nginx.ingress.kubernetes.io/enable-modsecurity"] == "true"
    assert (
        ingress_annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"] == "true"
    )
    assert ingress_annotations["nginx.ingress.kubernetes.io/modsecurity-snippet"]

    action = (
        await ops_test.model.applications["any"]
        .units[0]
        .run_action(
            "rpc",
            method="update_ingress",
            kwargs=json.dumps({"ingress_config": {"owasp-modsecurity-crs": False}}),
        )
    )
    await action.wait()
    await ops_test.model.wait_for_idle(status=ActiveStatus.name)

    ingress_annotations = kube.read_namespaced_ingress(
        "any-ingress", namespace=ops_test.model.name
    ).metadata.annotations
    assert "nginx.ingress.kubernetes.io/enable-modsecurity" not in ingress_annotations
    assert "nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs" not in ingress_annotations
    assert "nginx.ingress.kubernetes.io/modsecurity-snippet" not in ingress_annotations
