# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""nginx-ingress-integrator charm action tests."""
import unittest.mock

import pytest
from ops.testing import Harness

from tests.unit.conftest import K8sStub


@pytest.mark.usefixtures("k8s_stub")
def test_describe_ingresses_no_relation(harness: Harness):
    harness.begin_with_initial_hooks()
    action_event = unittest.mock.MagicMock()
    harness.charm._describe_ingresses_action(action_event)
    action_event.set_results.assert_called_once()
    assert action_event.set_results.call_args.args[0]["ingresses"].items == []


def test_describe_ingresses(harness: Harness, k8s_stub: K8sStub, nginx_route_relation):
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
    harness.begin_with_initial_hooks()
    nginx_route_relation.update_app_data({"service-hostname": "foo"})
    action_event = unittest.mock.MagicMock()
    harness.charm._describe_ingresses_action(action_event)
    action_event.set_results.assert_called_once()
    assert action_event.set_results.call_args.args[0]["ingresses"].items == []
