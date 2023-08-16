# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""nginx-ingress-integrator charm unit tests."""


from ops.testing import Harness

from charm import NginxIngressCharm
from tests.unit.conftest import K8sStub
from tests.unit.constants import TEST_NAMESPACE


def test_follower():
    """
    arrange: set up test harness in a follower unit.
    act: start the harness.
    assert: unit should enter waiting status with appropriate status message.
    """
    harness = Harness(NginxIngressCharm)
    harness.begin_with_initial_hooks()
    assert harness.charm.unit.status.name == "waiting"
    assert harness.charm.unit.status.message == "follower unit is idling"


def test_no_relation(harness: Harness, k8s_stub: K8sStub):
    """
    arrange: set up test harness without relations.
    act: start the harness.
    assert: unit should enter waiting status with appropriate status message.
    """
    harness.begin_with_initial_hooks()
    assert harness.charm.unit.status.name == "waiting"
    assert harness.charm.unit.status.message == "waiting for relation"
    assert k8s_stub.get_ingresses(TEST_NAMESPACE) == []
    assert k8s_stub.get_services(TEST_NAMESPACE) == []
    assert k8s_stub.get_endpoint_slices(TEST_NAMESPACE) == []


def test_incomplete_nginx_route(harness: Harness, k8s_stub: K8sStub, nginx_route_relation):
    """
    arrange: set up test harness and nginx-route relation.
    act: update the relation with incomplete data.
    assert: unit should enter blocked status with appropriate status message.
    """
    harness.begin_with_initial_hooks()
    assert harness.charm.unit.status.name == "waiting"
    assert harness.charm.unit.status.message == "waiting for relation"
    nginx_route_relation.update_app_data({"service-name": "app"})
    assert harness.charm.unit.status.name == "blocked"
    assert (
        harness.charm.unit.status.message
        == "Missing fields for nginx-route: service-hostname, service-port"
    )


def test_incomplete_ingress(harness: Harness, k8s_stub: K8sStub, ingress_relation):
    """
    arrange: set up test harness and ingress relation.
    act: update the relation with different incomplete data.
    assert: unit should enter blocked status with appropriate status message.
    """
    harness.begin_with_initial_hooks()
    assert harness.charm.unit.status.name == "waiting"
    assert harness.charm.unit.status.message == "waiting for relation"
    ingress_relation.update_app_data({"port": "8080"})
    assert harness.charm.unit.status.name == "blocked"
    assert (
        harness.charm.unit.status.message
        == "service-hostname is not configured for ingress relation"
    )
    assert k8s_stub.get_ingresses(TEST_NAMESPACE) == []
    harness.update_config({"service-hostname": "example.com"})
    assert harness.charm.unit.status.name == "blocked"
    assert harness.charm.unit.status.message == "no endpoints are provided in ingress relation"
    assert k8s_stub.get_ingresses(TEST_NAMESPACE) == []
    ingress_relation.update_unit_data({"ip": "10.0.0.1"})
    assert harness.charm.unit.status.name == "blocked"
    assert harness.charm.unit.status.message == "ingress options missing: [service_name]"
    assert k8s_stub.get_ingresses(TEST_NAMESPACE) == []


def test_no_permission(harness: Harness, k8s_stub: K8sStub, ingress_relation):
    """
    arrange: set up test harness.
    act: update kubernetes test stub to raise permission error.
    assert: unit should enter blocked status with appropriate status message.
    """
    k8s_stub.auth = False
    harness.begin_with_initial_hooks()
    assert harness.charm.unit.status.name == "blocked"
    assert (
        harness.charm.unit.status.message
        == "Insufficient permissions, try: `juju trust nginx-ingress-integrator --scope=cluster`"
    )
