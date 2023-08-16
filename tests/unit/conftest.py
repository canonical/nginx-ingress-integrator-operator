# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""nginx-ingress-integrator charm unit test fixtures."""


import copy
from collections import defaultdict
from functools import partial
from typing import Any, Dict, List, Union

import kubernetes
import ops.testing
import pytest

from charm import NginxIngressCharm


class K8sStub:
    """A test stub for kubernetes APIs."""

    def __init__(self):
        self.namespaces: defaultdict[str, dict] = defaultdict(
            lambda: {"ingress": {}, "service": {}, "endpoint_slice": {}}
        )
        self.auth = True
        self.ingress_classes = [
            kubernetes.client.V1IngressClass(
                metadata=kubernetes.client.V1ObjectMeta(
                    annotations={"ingressclass.kubernetes.io/is-default-class": "true"},
                    name="nginx-ingress",
                )
            )
        ]

    def _get_resource_dict(self, resource: str, namespace: str) -> Dict[str, Any]:
        return self.namespaces[namespace][resource]

    def get_ingresses(self, namespace: str) -> List[kubernetes.client.V1Ingress]:
        return list(self._get_resource_dict("ingress", namespace=namespace).values())

    def get_services(self, namespace: str) -> List[kubernetes.client.V1Service]:
        return list(self._get_resource_dict("service", namespace=namespace).values())

    def get_endpoint_slices(self, namespace: str) -> List[kubernetes.client.V1EndpointSlice]:
        return list(self._get_resource_dict("endpoint_slice", namespace=namespace).values())

    def create_namespaced_resource(
        self,
        resource: str,
        namespace: str,
        body: Union[
            kubernetes.client.V1EndpointSlice,
            kubernetes.client.V1Service,
            kubernetes.client.V1Ingress,
        ],
    ):
        if not self.auth:
            raise kubernetes.client.ApiException(status=403)
        resources = self._get_resource_dict(resource=resource, namespace=namespace)
        name = body.metadata.name
        if name in resources:
            raise ValueError(f"can't overwrite existing {resource} {name}")
        resources[name] = body

    def patch_namespaced_resource(
        self,
        resource: str,
        namespace: str,
        name: str,
        body: Union[
            kubernetes.client.V1EndpointSlice,
            kubernetes.client.V1Service,
            kubernetes.client.V1Ingress,
        ],
    ) -> None:
        if not self.auth:
            raise kubernetes.client.ApiException(status=403)
        resources = self._get_resource_dict(resource=resource, namespace=namespace)
        if name not in resources:
            raise ValueError(f"{resource} {name} in {namespace} not found")
        resources[name] = body

    def list_namespaced_resource(
        self, resource: str, namespace: str, label_selector: str
    ) -> Union[
        kubernetes.client.V1EndpointSliceList,
        kubernetes.client.V1ServiceList,
        kubernetes.client.V1IngressList,
    ]:
        if not self.auth:
            raise kubernetes.client.ApiException(status=403)
        resources = list(self._get_resource_dict(resource=resource, namespace=namespace).values())
        if resource == "endpoint_slice":
            return kubernetes.client.V1EndpointSliceList(items=resources)
        elif resource == "service":
            return kubernetes.client.V1ServiceList(items=resources)
        elif resource == "ingress":
            return kubernetes.client.V1IngressList(items=resources)
        else:
            raise ValueError(f"unknown resource type: {resource}")

    def delete_namespaced_resource(self, resource: str, namespace: str, name: str):
        if not self.auth:
            raise kubernetes.client.ApiException(status=403)
        resources = self._get_resource_dict(resource=resource, namespace=namespace)
        if name not in resources:
            raise ValueError(f"{resource} {name} in {namespace} not found")
        del resources[name]


@pytest.fixture
def k8s_stub(monkeypatch: pytest.MonkeyPatch) -> K8sStub:
    stub = K8sStub()
    for action in ("create", "patch", "list", "delete"):
        monkeypatch.setattr(
            f"kubernetes.client.DiscoveryV1Api.{action}_namespaced_endpoint_slice",
            partial(getattr(stub, f"{action}_namespaced_resource"), "endpoint_slice"),
        )
        monkeypatch.setattr(
            f"kubernetes.client.CoreV1Api.{action}_namespaced_service",
            partial(getattr(stub, f"{action}_namespaced_resource"), "service"),
        )
        ingress_action = action.replace("patch", "replace")
        monkeypatch.setattr(
            f"kubernetes.client.NetworkingV1Api.{ingress_action}_namespaced_ingress",
            partial(getattr(stub, f"{action}_namespaced_resource"), "ingress"),
        )
    monkeypatch.setattr(
        "kubernetes.client.NetworkingV1Api.list_ingress_class",
        lambda _: kubernetes.client.V1IngressClassList(items=stub.ingress_classes),
    )
    monkeypatch.setattr("kubernetes.config.load_incluster_config", lambda: None)
    monkeypatch.setattr(NginxIngressCharm, "_report_ingress_ips", lambda _: ["127.0.0.1"])
    monkeypatch.setattr(NginxIngressCharm, "_report_service_ips", lambda _: ["10.0.0.1"])
    return stub


@pytest.fixture(name="harness")
def harness_fixture() -> ops.testing.Harness:
    harness = ops.testing.Harness(NginxIngressCharm)
    harness.set_model_name("test")
    harness.set_leader(True)
    return harness


class RelationFixture:
    def __init__(
        self,
        harness: ops.testing.Harness,
        relation_name: str,
        example_app_data: Dict[str, str],
        example_unit_data: Dict[str, str],
    ):
        self._harness = harness
        self._relation_name = relation_name
        self._remote_app = f"{relation_name}-remote"
        self._remote_unit = f"{self._remote_app}/0"
        self._relation_id = self._harness.add_relation(self._relation_name, self._remote_app)
        self._harness.add_relation_unit(self._relation_id, self._remote_unit)
        self._example_app_data = example_app_data
        self._example_unit_data = example_unit_data

    def update_app_data(self, data: Dict[str, str]) -> None:
        self._harness.update_relation_data(self._relation_id, self._remote_app, data)

    def update_unit_data(self, data: Dict[str, str]) -> None:
        self._harness.update_relation_data(self._relation_id, self._remote_unit, data)

    def remove_relation(self) -> None:
        self._harness.remove_relation_unit(self._relation_id, self._remote_unit)
        self._harness.remove_relation(self._relation_id)

    def gen_example_app_data(self) -> Dict[str, str]:
        return copy.copy(self._example_app_data)

    def gen_example_unit_data(self) -> Dict[str, str]:
        return copy.copy(self._example_unit_data)

    @property
    def relation(self) -> ops.Relation:
        return self._harness.charm.model.get_relation(
            relation_name=self._relation_name, relation_id=self._relation_id
        )


@pytest.fixture
def nginx_route_relation(harness: ops.testing.Harness) -> RelationFixture:
    return RelationFixture(
        harness,
        relation_name="nginx-route",
        example_app_data={
            "service-hostname": "example.com",
            "service-port": "8080",
            "service-namespace": "test",
            "service-name": "app",
        },
        example_unit_data={},
    )


@pytest.fixture
def ingress_relation(harness: ops.testing.Harness) -> RelationFixture:
    return RelationFixture(
        harness,
        relation_name="ingress",
        example_app_data={
            "port": "8080",
            "model": "test",
            "name": "app",
        },
        example_unit_data={"host": "test.svc.cluster.local", "ip": "10.0.0.1"},
    )
