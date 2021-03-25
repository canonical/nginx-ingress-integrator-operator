# Copyright 2021 Tom Haddon
# See LICENSE file for licensing details.

import mock
import unittest

import kubernetes

from ops.model import ActiveStatus
from ops.testing import Harness
from charm import CharmK8SIngressCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(CharmK8SIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @mock.patch('charm.CharmK8SIngressCharm._report_service_ips')
    @mock.patch('charm.CharmK8SIngressCharm._define_ingress')
    @mock.patch('charm.CharmK8SIngressCharm._define_service')
    def test_config_changed(self, _define_service, _define_ingress, _report_service_ips):
        """Test our config changed handler."""
        # First of all test, with leader set to True.
        self.harness.set_leader(True)
        _report_service_ips.return_value = ["10.0.1.12"]
        # Confirm our _define_ingress and _define_service methods haven't been called.
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # Test if config-changed is called with service-name empty, our methods still
        # aren't called.
        self.harness.update_config({"service-name": ""})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # And now test if we set a service-name config, our methods are called.
        self.harness.update_config({"service-name": "gunicorn"})
        self.assertEqual(_define_ingress.call_count, 1)
        self.assertEqual(_define_service.call_count, 1)
        # Confirm status is as expected.
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus('Ingress with service IP(s): 10.0.1.12'))
        # And now test with leader is False.
        _define_ingress.reset_mock()
        _define_service.reset_mock()
        self.harness.set_leader(False)
        self.harness.update_config({"service-name": ""})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # Leader False, but service-name defined should still do nothing.
        self.harness.update_config({"service-name": "gunicorn"})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # Confirm status is as expected.
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())

    def test_get_k8s_ingress(self):
        """Test getting our definition of a k8s ingress."""
        self.harness.disable_hooks()
        self.harness.update_config({"service-name": "gunicorn", "service-port": 80, "service-hostname": "foo.internal"})
        expected = kubernetes.client.NetworkingV1beta1Ingress(
            api_version="networking.k8s.io/v1beta1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
            ),
            spec=kubernetes.client.NetworkingV1beta1IngressSpec(
                rules=[
                    kubernetes.client.NetworkingV1beta1IngressRule(
                        host="foo.internal",
                        http=kubernetes.client.NetworkingV1beta1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.NetworkingV1beta1HTTPIngressPath(
                                    path="/",
                                    backend=kubernetes.client.NetworkingV1beta1IngressBackend(
                                        service_port=80,
                                        service_name="gunicorn-service",
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
        )
        self.assertEqual(self.harness.charm._get_k8s_ingress(), expected)

    def test_get_k8s_service(self):
        """Test getting our definition of a k8s service."""
        self.harness.disable_hooks()
        self.harness.update_config({"service-name": "gunicorn", "service-port": 80})
        expected = kubernetes.client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=kubernetes.client.V1ObjectMeta(name="gunicorn-service"),
            spec=kubernetes.client.V1ServiceSpec(
                selector={"app.kubernetes.io/name": "gunicorn"},
                ports=[
                    kubernetes.client.V1ServicePort(
                        name="tcp-80",
                        port=80,
                        target_port=80,
                    )
                ],
            ),
        )
        self.assertEqual(self.harness.charm._get_k8s_service(), expected)
