# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the zero downtime upgrade process from legacy ingress relation to nginx-route."""

import json
from pathlib import Path

import kubernetes
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

ANY_CHARM_COMMON = """
from any_charm_base import AnyCharmBase
from ingress import IngressRequires
from nginx_route import require_nginx_route


class AnyCharm(AnyCharmBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
"""

ANY_CHARM_INGRESS = (
    ANY_CHARM_COMMON
    + """
        self.ingress = IngressRequires(
            self,
            {
                "service-hostname": self.app.name,
                "service-name": self.app.name,
                "service-port": 8080,
            },
        )
"""
)

ANY_CHARM_NGINX_ROUTE = (
    ANY_CHARM_COMMON
    + """
        require_nginx_route(
            charm=self,
            service_hostname=self.app.name,
            service_name=self.app.name,
            service_port=8080,
        )
"""
)

ANY_CHARM_DUAL = (
    ANY_CHARM_INGRESS
    + """
        require_nginx_route(
            charm=self,
            service_hostname=self.app.name,
            service_name=self.app.name,
            service_port=8080,
        )
"""
)


async def test_zero_downtime(
    ops_test: OpsTest, model: Model, build_and_deploy_ingress, wait_for_ingress
):
    """Test the zero downtime upgrade process from legacy ingress relation to nginx-route."""
    ingress: Application = await build_and_deploy_ingress()
    lib_path = Path("lib/charms/nginx_ingress_integrator/v0")
    src_overwrite = {
        "any_charm.py": ANY_CHARM_INGRESS,
        "ingress.py": (lib_path / "ingress.py").read_text(),
        "nginx_route.py": (lib_path / "nginx_route.py").read_text(),
    }
    any_charm: Application = await model.deploy(
        "any-charm", channel="beta", config={"src-overwrite": json.dumps(src_overwrite)}
    )
    await model.relate("any-charm:ingress", f"{ingress.name}:ingress")
    await model.wait_for_idle()
    ingress_name = "any-charm-ingress"
    service_name = "any-charm-service"
    await wait_for_ingress(ingress_name)

    kubernetes.config.load_kube_config()
    networking_api = kubernetes.client.NetworkingV1Api()
    core_api = kubernetes.client.CoreV1Api()
    ingress_uid = networking_api.read_namespaced_ingress(
        name=ingress_name, namespace=model.name
    ).metadata.uid
    service_uid = core_api.read_namespaced_service(
        name=service_name, namespace=model.name
    ).metadata.uid

    src_overwrite["any_charm.py"] = ANY_CHARM_DUAL
    await any_charm.set_config({"src-overwrite": src_overwrite})
    await model.wait_for_idle()
    await model.relate("any-charm:nginx-route", f"{ingress.name}:nginx-route")
    await model.wait_for_idle()

    assert len(networking_api.list_namespaced_ingress(namespace=model.name).items) == 1

    await ops_test.juju("remove-relation", "any-charm:ingress", f"{ingress.name}:ingress")
    await model.wait_for_idle()
    src_overwrite["any_charm.py"] = ANY_CHARM_NGINX_ROUTE
    await any_charm.set_config({"src-overwrite": src_overwrite})
    await model.wait_for_idle()

    assert (
        ingress_uid
        == networking_api.read_namespaced_ingress(
            name=ingress_name, namespace=model.name
        ).metadata.uid
    )
    assert (
        service_uid
        == core_api.read_namespaced_service(name=service_name, namespace=model.name).metadata.uid
    )
