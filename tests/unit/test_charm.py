# Copyright 2021 Tom Haddon
# See LICENSE file for licensing details.

import unittest

from unittest.mock import MagicMock, patch

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

    @patch('charm.CharmK8SIngressCharm._report_service_ips')
    @patch('charm.CharmK8SIngressCharm._define_ingress')
    @patch('charm.CharmK8SIngressCharm._define_service')
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

    def test_namespace(self):
        """Test for the namespace property."""
        # If charm config and _stored is empty, use model name.
        self.assertEqual(self.harness.charm._stored.ingress_relation_data.get("service-namespace"), None)
        self.assertEqual(self.harness.charm.config["service-namespace"], "")
        self.assertEqual(self.harness.charm._namespace, self.harness.charm.model.name)
        # If we set config, that takes precedence.
        self.harness.update_config({"service-namespace": "mymodelname"})
        self.assertEqual(self.harness.charm._namespace, "mymodelname")
        # And if we set _stored, that takes precedence.
        self.harness.charm._stored.ingress_relation_data["service-namespace"] = "relationnamespace"
        self.assertEqual(self.harness.charm._namespace, "relationnamespace")

    def test_service_port(self):
        """Test the service-port property."""
        # First set via config.
        self.harness.update_config({"service-port": 80})
        self.assertEqual(self.harness.charm._service_port, 80)
        # Now set via the StoredState. This will be set to a string, as all
        # relation data must be a string.
        self.harness.charm._stored.ingress_relation_data["service-port"] = "88"
        self.assertEqual(self.harness.charm._service_port, 88)

    @patch('charm.CharmK8SIngressCharm._on_config_changed')
    def test_on_ingress_relation_changed(self, _on_config_changed):
        """Test ingress relation changed handler."""
        # Confirm we do nothing if we're not the leader.
        self.assertFalse(self.harness.charm.unit.is_leader())
        mock_event = MagicMock()
        self.assertEqual(self.harness.charm._stored.ingress_relation_data, {})
        self.harness.charm._on_ingress_relation_changed(mock_event)
        # Confirm no relation data has been set.
        self.assertEqual(self.harness.charm._stored.ingress_relation_data, {})
        # Confirm config_changed hasn't been called.
        _on_config_changed.assert_not_called()

        # Now test on the leader, but with missing fields in the relation data.
        # We don't want leader-set to fire.
        self.harness.disable_hooks()
        self.harness.set_leader(True)
        mock_event.unit = "gunicorn-0"
        mock_event.relation.data = {"gunicorn-0": {"service-name": "gunicorn"}}
        with self.assertLogs(level="ERROR") as logger:
            self.harness.charm._on_ingress_relation_changed(mock_event)
            msg = "ERROR:charm:Missing required data fields for ingress relation: service-hostname, service-port"
            self.assertEqual(sorted(logger.output), [msg])
            # Confirm no relation data has been set.
            self.assertEqual(self.harness.charm._stored.ingress_relation_data, {})
            # Confirm config_changed hasn't been called.
            _on_config_changed.assert_not_called()

        # Now test with complete relation data.
        mock_event.relation.data = {
            "gunicorn-0": {
                "service-hostname": "foo.internal",
                "service-name": "gunicorn",
                "service-port": "80",
            }
        }
        self.harness.charm._on_ingress_relation_changed(mock_event)
        expected = {
            "max-body-size": None,
            "service-hostname": "foo.internal",
            "service-name": "gunicorn",
            "service-namespace": None,
            "service-port": "80",
            "session-cookie-max-age": None,
            "tls-secret-name": None,
        }
        self.assertEqual(self.harness.charm._stored.ingress_relation_data, expected)
        # Confirm config_changed has been called.
        _on_config_changed.assert_called_once()

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
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
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
        # Test with TLS.
        expected = kubernetes.client.NetworkingV1beta1Ingress(
            api_version="networking.k8s.io/v1beta1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
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
                ],
                tls=kubernetes.client.NetworkingV1beta1IngressTLS(
                    hosts=["foo.internal"],
                    secret_name="gunicorn_tls",
                ),
            ),
        )
        self.harness.update_config({"tls-secret-name": "gunicorn_tls"})
        self.assertEqual(self.harness.charm._get_k8s_ingress(), expected)
        # Test max_body_size and session-cookie-max-age config options.
        self.harness.update_config({"tls-secret-name": "", "max-body-size": 0, "session-cookie-max-age": 3600})
        expected = kubernetes.client.NetworkingV1beta1Ingress(
            api_version="networking.k8s.io/v1beta1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/affinity": "cookie",
                    "nginx.ingress.kubernetes.io/affinity-mode": "balanced",
                    "nginx.ingress.kubernetes.io/proxy-body-size": "0m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/session-cookie-change-on-failure": "true",
                    "nginx.ingress.kubernetes.io/session-cookie-max-age": "3600",
                    "nginx.ingress.kubernetes.io/session-cookie-name": "GUNICORN_AFFINITY",
                    "nginx.ingress.kubernetes.io/session-cookie-samesite": "Lax",
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
