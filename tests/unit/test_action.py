# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""nginx-ingress-integrator charm action tests."""
import unittest.mock

import pytest
from ops.testing import Harness

from tests.unit.conftest import K8sStub


@pytest.mark.usefixtures("k8s_stub")
def test_describe_ingresses_no_relation(harness: Harness):
    """
    arrange: set up test harness.
    act: run the describe-ingresses action handler.
    assert: describe-ingresses action handler should return the empty result.
    """
    harness.begin_with_initial_hooks()
    action_event = unittest.mock.MagicMock()
    harness.charm._describe_ingresses_action(action_event)
    action_event.set_results.assert_called_once()
    assert action_event.set_results.call_args.args[0]["ingresses"].items == []


def test_describe_ingresses(harness: Harness, k8s_stub: K8sStub, nginx_route_relation):
    """
    arrange: set up test harness and the nginx-route relation.
    act: run the describe-ingresses action handler.
    assert: describe-ingresses action handler should return the ingress resource created for the
        nginx-route relation.
    """
    harness.begin_with_initial_hooks()
    nginx_route_relation.update_app_data(nginx_route_relation.gen_example_app_data())
    action_event = unittest.mock.MagicMock()
    harness.charm._describe_ingresses_action(action_event)
    action_event.set_results.assert_called_once()
    assert action_event.set_results.call_args.args[0]["ingresses"].items == k8s_stub.get_ingresses(
        harness.model.name
    )


def test_describe_ingresses_invalid_relation(
    harness: Harness, k8s_stub: K8sStub, nginx_route_relation
):
    """
    arrange: set up test harness and the nginx-route relation.
    act: provide invalid relation data in nginx-route relation run the describe-ingresses
        action handler.
    assert: describe-ingresses action handler should return the empty result.
    """
    harness.begin_with_initial_hooks()
    nginx_route_relation.update_app_data({"service-hostname": "foo"})
    action_event = unittest.mock.MagicMock()
    harness.charm._describe_ingresses_action(action_event)
    action_event.set_results.assert_called_once()
    assert action_event.set_results.call_args.args[0]["ingresses"].items == []
