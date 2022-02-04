# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from unittest.mock import MagicMock, patch

import kubernetes
import kubernetes.client

from ops.model import (
    ActiveStatus,
    BlockedStatus,
)
from ops.testing import Harness
from charm import NginxIngressCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch('charm.NginxIngressCharm._report_service_ips')
    @patch('charm.NginxIngressCharm._define_ingress')
    @patch('charm.NginxIngressCharm._define_service')
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
        self.assertEqual(
            self.harness.charm.unit.status, ActiveStatus('Ingress with service IP(s): 10.0.1.12')
        )
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

        # Confirm if we get a 403 error from k8s API we block with an appropriate message.
        _define_ingress.reset_mock()
        _define_service.reset_mock()
        _define_service.side_effect = kubernetes.client.exceptions.ApiException(status=403)
        self.harness.set_leader(True)
        self.harness.update_config()
        self.assertEqual(
            self.harness.charm.unit.status,
            BlockedStatus(
                "Insufficient permissions, try: "
                "`juju trust nginx-ingress-integrator --scope=cluster`"
            ),
        )

    def test_get_ingress_relation_data(self):
        """Test for getting our ingress relation data."""
        # Confirm we don't have any relation data yet in the relevant properties
        self.assertEqual(self.harness.charm._service_name, "")
        self.assertEqual(self.harness.charm._service_hostname, "")
        self.assertEqual(self.harness.charm._service_port, 0)
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        # And now confirm we have the expected data in the relevant properties.
        self.assertEqual(self.harness.charm._service_name, "gunicorn")
        self.assertEqual(self.harness.charm._service_hostname, "foo.internal")
        self.assertEqual(self.harness.charm._service_port, 80)

    def test_multiple_routes_with_relation_data(self):
        """Test for getting our ingress relation data."""
        # Confirm we don't have any relation data yet in the relevant properties
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
            "path-routes": "/admin/,/portal/",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)

        # Test multiple paths
        expected = [
            {
                'backend': {
                    'resource': None,
                    'service': {
                        'name': 'gunicorn-service',
                        'port': {
                            'name': None,
                            'number': 80,
                        },
                    },
                },
                'path': '/admin/',
                'path_type': 'Prefix',
            },
            {
                'backend': {
                    'resource': None,
                    'service': {
                        'name': 'gunicorn-service',
                        'port': {
                            'name': None,
                            'number': 80,
                        },
                    },
                },
                'path': '/portal/',
                'path_type': 'Prefix',
            },
        ]
        result_dict = self.harness.charm._get_k8s_ingress().to_dict()
        self.assertEqual(result_dict['spec']['rules'][0]['http']['paths'], expected)

    def test_max_body_size(self):
        """Test for the max-body-size property."""
        # First set via config.
        self.harness.update_config({"max-body-size": 80})
        self.assertEqual(self.harness.charm._max_body_size, "80m")
        # Now set via the StoredState. This will be set to a string, as all
        # relation data must be a string.
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "max-body-size": "88",
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        # Still 80 because it's set via config.
        self.assertEqual(self.harness.charm._max_body_size, "80m")
        self.harness.update_config({"max-body-size": 0})
        # Now it's the value from the relation.
        self.assertEqual(self.harness.charm._max_body_size, "88m")

    def test_namespace(self):
        """Test for the namespace property."""
        # If charm config and relation data is empty, use model name.
        self.assertEqual(self.harness.charm.model.get_relation("ingress"), None)
        self.assertEqual(self.harness.charm.config["service-namespace"], "")
        self.assertEqual(self.harness.charm._namespace, self.harness.charm.model.name)
        # If we set config, that takes precedence.
        self.harness.update_config({"service-namespace": "mymodelname"})
        self.assertEqual(self.harness.charm._namespace, "mymodelname")
        # And if we set relation data, config still takes precedence.
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        self.assertEqual(self.harness.charm._namespace, "mymodelname")
        self.harness.update_config({"service-namespace": ""})
        # Now it reverts to the model name, because the relation isn't passing it.
        self.assertEqual(self.harness.charm._namespace, self.harness.charm.model.name)
        # And check if we're passing relation data including the service-namespace
        # it gets set based on that.
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-namespace": "relationnamespace",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        self.assertEqual(self.harness.charm._namespace, "relationnamespace")

    def test_owasp_modsecurity_crs(self):
        """Test the owasp-modsecurity-crs property."""
        # Test undefined.
        self.assertEqual(self.harness.charm._owasp_modsecurity_crs, False)
        # Test we have no annotations with this set to False.
        self.harness.disable_hooks()
        self.harness.update_config(
            {
                "service-hostname": "foo.internal",
                "service-name": "gunicorn",
                "service-port": 80,
            }
        )
        result_dict = self.harness.charm._get_k8s_ingress().to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)
        # Test if we set the value we get the correct annotations and the
        # correct charm property.
        self.harness.update_config({"owasp-modsecurity-crs": True})
        self.assertEqual(self.harness.charm._owasp_modsecurity_crs, True)
        result_dict = self.harness.charm._get_k8s_ingress().to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/enable-modsecurity": "true",
            "nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs": "true",
            "nginx.ingress.kubernetes.io/modsecurity-snippet": (
                "SecRuleEngine On\nInclude /etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf"
            ),
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

    def test_retry_errors(self):
        """Test the retry-errors property."""
        # Test empty value.
        self.assertEqual(self.harness.charm._retry_errors, "")
        # Test we deal with spaces or not spaces properly.
        self.harness.update_config({"retry-errors": "error, timeout, http_502, http_503"})
        self.assertEqual(self.harness.charm._retry_errors, "error timeout http_502 http_503")
        self.harness.update_config({"retry-errors": "error,timeout,http_502,http_503"})
        self.assertEqual(self.harness.charm._retry_errors, "error timeout http_502 http_503")
        # Test unknown value.
        self.harness.update_config({"retry-errors": "error,timeout,http_502,http_418"})
        self.assertEqual(self.harness.charm._retry_errors, "error timeout http_502")

    def test_service_port(self):
        """Test the service-port property."""
        # First set via config.
        self.harness.update_config({"service-port": 80})
        self.assertEqual(self.harness.charm._service_port, 80)
        # Now set via the relation.
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "88",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        # Config still overrides the relation value.
        self.assertEqual(self.harness.charm._service_port, 80)
        self.harness.update_config({"service-port": 0})
        # Now it's the value from the relation.
        self.assertEqual(self.harness.charm._service_port, 88)

    def test_service_hostname(self):
        """Test the service-hostname property."""
        # First set via config.
        self.harness.update_config({"service-hostname": "foo.internal"})
        self.assertEqual(self.harness.charm._service_hostname, "foo.internal")
        # Now set via the relation.
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo-bar.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        # Config still overrides the relation value.
        self.assertEqual(self.harness.charm._service_hostname, "foo.internal")
        self.harness.update_config({"service-hostname": ""})
        # Now it's the value from the relation.
        self.assertEqual(self.harness.charm._service_hostname, "foo-bar.internal")

    def test_session_cookie_max_age(self):
        """Test the session-cookie-max-age property."""
        # First set via config.
        self.harness.update_config({"session-cookie-max-age": 3600})
        self.assertEqual(self.harness.charm._session_cookie_max_age, "3600")
        # Confirm if we set this to 0 we get a False value, e.g. it doesn't
        # return a string of "0" which would be evaluated to True.
        self.harness.update_config({"session-cookie-max-age": 0})
        self.assertFalse(self.harness.charm._session_cookie_max_age)
        # Now set via the relation.
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
            "session-cookie-max-age": "3688",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        self.assertEqual(self.harness.charm._session_cookie_max_age, "3688")

    def test_tls_secret_name(self):
        """Test the tls-secret-name property."""
        self.harness.update_config({"tls-secret-name": "gunicorn-tls"})
        self.assertEqual(self.harness.charm._tls_secret_name, "gunicorn-tls")
        # Now set via the relation.
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
            "tls-secret-name": "gunicorn-tls-new",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        # Config still overrides the relation data.
        self.assertEqual(self.harness.charm._tls_secret_name, "gunicorn-tls")
        self.harness.update_config({"tls-secret-name": ""})
        # Now it's the value from the relation.
        self.assertEqual(self.harness.charm._tls_secret_name, "gunicorn-tls-new")

    def test_rewrite_enabled_property(self):
        """Test for enabling request rewrites."""
        # First set via config.
        self.harness.update_config({"rewrite-enabled": True})
        self.assertEqual(self.harness.charm._rewrite_enabled, True)
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "rewrite-enabled": "False",
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        # Still /test-target because it's set via config.
        self.assertEqual(self.harness.charm._rewrite_enabled, True)
        self.harness.update_config({"rewrite-enabled": ""})
        self.assertEqual(self.harness.charm._rewrite_enabled, False)

    def test_rewrite_annotations(self):
        self.harness.disable_hooks()
        self.harness.update_config(
            {
                "service-hostname": "foo.internal",
                "service-name": "gunicorn",
                "service-port": 80,
            }
        )
        result_dict = self.harness.charm._get_k8s_ingress().to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

        self.harness.update_config({"rewrite-enabled": False})
        result_dict = self.harness.charm._get_k8s_ingress().to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

        self.harness.update_config({"rewrite-target": "/test-target"})
        self.harness.update_config({"rewrite-enabled": True})

        expected = {
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/test-target",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        result_dict = self.harness.charm._get_k8s_ingress().to_dict()
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

    @patch('charm.NginxIngressCharm._on_config_changed')
    def test_on_ingress_relation_changed(self, _on_config_changed):
        """Test ingress relation changed handler."""
        # Confirm we do nothing if we're not the leader.
        self.assertFalse(self.harness.charm.unit.is_leader())
        # Confirm config_changed hasn't been called.
        _on_config_changed.assert_not_called()

        # Now test on the leader, but with missing fields in the relation data.
        # We don't want leader-set to fire.
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation('ingress', 'gunicorn')
        self.harness.add_relation_unit(relation_id, 'gunicorn/0')
        relations_data = {
            "service-name": "gunicorn",
        }
        with self.assertLogs(level="ERROR") as logger:
            self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
            msg = (
                "ERROR:charms.nginx_ingress_integrator.v0.ingress:Missing required data fields "
                "for ingress relation: service-hostname, service-port"
            )
            self.assertEqual(sorted(logger.output), [msg])
            # Confirm blocked status.
            self.assertEqual(
                self.harness.charm.unit.status,
                BlockedStatus("Missing fields for ingress: service-hostname, service-port"),
            )

        # Now test with complete relation data.
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, 'gunicorn', relations_data)
        # Test we get the values we expect:
        self.assertEqual(self.harness.charm._service_hostname, "foo.internal")
        self.assertEqual(self.harness.charm._service_name, "gunicorn")
        self.assertEqual(self.harness.charm._service_port, 80)

    @patch('charm.NginxIngressCharm._remove_ingress')
    @patch('charm.NginxIngressCharm._remove_service')
    def test_on_ingress_relation_broken(self, _remove_service, _remove_ingress):
        """Test relation-broken."""
        # Call the test test_on_ingress_relation_changed first
        # to make sure the relation is created and therefore can be removed.
        self.test_on_ingress_relation_changed()
        relation = self.harness.charm.model.get_relation("ingress")
        self.harness.charm.on.ingress_relation_broken.emit(relation)
        self.assertEqual(_remove_ingress.call_count, 1)
        self.assertEqual(_remove_service.call_count, 1)

    def test_get_k8s_ingress(self):
        """Test getting our definition of a k8s ingress."""
        self.harness.disable_hooks()
        self.harness.update_config(
            {"service-hostname": "foo.internal", "service-name": "gunicorn", "service-port": 80}
        )
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
            ),
            spec=kubernetes.client.V1IngressSpec(
                rules=[
                    kubernetes.client.V1IngressRule(
                        host="foo.internal",
                        http=kubernetes.client.V1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
        )
        self.assertEqual(self.harness.charm._get_k8s_ingress(), expected)
        # Test additional hostnames
        self.harness.update_config({"additional-hostnames": "bar.internal,foo.external"})
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
            ),
            spec=kubernetes.client.V1IngressSpec(
                rules=[
                    kubernetes.client.V1IngressRule(
                        host="foo.internal",
                        http=kubernetes.client.V1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
                                    ),
                                )
                            ]
                        ),
                    ),
                    kubernetes.client.V1IngressRule(
                        host="bar.internal",
                        http=kubernetes.client.V1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
                                    ),
                                )
                            ]
                        ),
                    ),
                    kubernetes.client.V1IngressRule(
                        host="foo.external",
                        http=kubernetes.client.V1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
                                    ),
                                )
                            ]
                        ),
                    ),
                ]
            ),
        )
        self.assertEqual(self.harness.charm._get_k8s_ingress(), expected)
        self.harness.update_config({"additional-hostnames": ""})
        # Test multiple paths
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
            ),
            spec=kubernetes.client.V1IngressSpec(
                rules=[
                    kubernetes.client.V1IngressRule(
                        host="foo.internal",
                        http=kubernetes.client.V1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/admin",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
                                    ),
                                ),
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/portal",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
                                    ),
                                ),
                            ]
                        ),
                    )
                ]
            ),
        )
        self.harness.update_config({"path-routes": "/admin,/portal"})
        self.assertEqual(self.harness.charm._get_k8s_ingress(), expected)
        self.harness.update_config({"path-routes": "/"})
        # Test with TLS.
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                },
            ),
            spec=kubernetes.client.V1IngressSpec(
                rules=[
                    kubernetes.client.V1IngressRule(
                        host="foo.internal",
                        http=kubernetes.client.V1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
                                    ),
                                )
                            ]
                        ),
                    )
                ],
                tls=[
                    kubernetes.client.V1IngressTLS(
                        hosts=["foo.internal"],
                        secret_name="gunicorn_tls",
                    ),
                ],
            ),
        )
        self.harness.update_config({"tls-secret-name": "gunicorn_tls"})
        self.assertEqual(self.harness.charm._get_k8s_ingress(), expected)
        # Test ingress-class, max_body_size, retry_http_errors and
        # session-cookie-max-age config options.
        self.harness.update_config(
            {
                "ingress-class": "nginx",
                "max-body-size": 10,
                "retry-errors": "error,timeout,http_502,http_503",
                "session-cookie-max-age": 3600,
                "tls-secret-name": "",
            }
        )
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/affinity": "cookie",
                    "nginx.ingress.kubernetes.io/affinity-mode": "balanced",
                    "nginx.ingress.kubernetes.io/proxy-body-size": "10m",
                    "nginx.ingress.kubernetes.io/proxy-next-upstream": (
                        "error timeout http_502 http_503"
                    ),
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/session-cookie-change-on-failure": "true",
                    "nginx.ingress.kubernetes.io/session-cookie-max-age": "3600",
                    "nginx.ingress.kubernetes.io/session-cookie-name": "GUNICORN_AFFINITY",
                    "nginx.ingress.kubernetes.io/session-cookie-samesite": "Lax",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
            ),
            spec=kubernetes.client.V1IngressSpec(
                rules=[
                    kubernetes.client.V1IngressRule(
                        host="foo.internal",
                        http=kubernetes.client.V1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
        )
        self.assertEqual(self.harness.charm._get_k8s_ingress(), expected)
        # Test limit-whitelist on its own makes no change.
        self.harness.update_config({"limit-whitelist": "10.0.0.0/16"})
        self.assertEqual(self.harness.charm._get_k8s_ingress(), expected)
        # And if we set limit-rps we get both. Unset other options to minimize output.
        self.harness.update_config(
            {
                "limit-rps": 5,
                "ingress-class": "",
                "max-body-size": 0,
                "retry-errors": "",
                "session-cookie-max-age": 0,
            }
        )
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-ingress",
                annotations={
                    "nginx.ingress.kubernetes.io/limit-rps": "5",
                    "nginx.ingress.kubernetes.io/limit-whitelist": "10.0.0.0/16",
                    "nginx.ingress.kubernetes.io/proxy-body-size": "0m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
            ),
            spec=kubernetes.client.V1IngressSpec(
                rules=[
                    kubernetes.client.V1IngressRule(
                        host="foo.internal",
                        http=kubernetes.client.V1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.V1HTTPIngressPath(
                                    path="/",
                                    path_type="Prefix",
                                    backend=kubernetes.client.V1IngressBackend(
                                        service=kubernetes.client.V1IngressServiceBackend(
                                            name="gunicorn-service",
                                            port=kubernetes.client.V1ServiceBackendPort(
                                                number=80,
                                            ),
                                        ),
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


INGRESS_CLASS_PUBLIC_DEFAULT = kubernetes.client.V1beta1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={
            'ingressclass.kubernetes.io/is-default-class': 'true',
        },
        name='public',
    ),
    spec=kubernetes.client.V1beta1IngressClassSpec(
        controller='k8s.io/ingress-nginx',
    ),
)

INGRESS_CLASS_PRIVATE = kubernetes.client.V1beta1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={},
        name='private',
    ),
    spec=kubernetes.client.V1beta1IngressClassSpec(
        controller='k8s.io/ingress-nginx',
    ),
)

INGRESS_CLASS_PRIVATE_DEFAULT = kubernetes.client.V1beta1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={
            'ingressclass.kubernetes.io/is-default-class': 'true',
        },
        name='private',
    ),
    spec=kubernetes.client.V1beta1IngressClassSpec(
        controller='k8s.io/ingress-nginx',
    ),
)

ZERO_INGRESS_CLASS_LIST = kubernetes.client.V1beta1IngressClassList(items=[])

ONE_INGRESS_CLASS_LIST = kubernetes.client.V1beta1IngressClassList(
    items=[
        INGRESS_CLASS_PUBLIC_DEFAULT,
    ],
)

TWO_INGRESS_CLASSES_LIST = kubernetes.client.V1beta1IngressClassList(
    items=[
        INGRESS_CLASS_PUBLIC_DEFAULT,
        INGRESS_CLASS_PRIVATE,
    ]
)

TWO_INGRESS_CLASSES_LIST_TWO_DEFAULT = kubernetes.client.V1beta1IngressClassList(
    items=[
        INGRESS_CLASS_PUBLIC_DEFAULT,
        INGRESS_CLASS_PRIVATE_DEFAULT,
    ]
)


def _make_mock_api_list_ingress_class(return_value):
    mock_api = MagicMock()
    mock_api.list_ingress_class.return_value = return_value
    return mock_api


class TestCharmLookUpAndSetIngressClass(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.harness.disable_hooks()
        self.harness.update_config(
            {"service-hostname": "foo.internal", "service-name": "gunicorn", "service-port": 80}
        )

    def test_zero_ingress_class(self):
        """If there are no ingress classes, there's nothing to choose from."""
        api = _make_mock_api_list_ingress_class(ZERO_INGRESS_CLASS_LIST)
        body = self.harness.charm._get_k8s_ingress()
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertIsNone(body.spec.ingress_class_name)

    def test_one_ingress_class(self):
        """If there's one default ingress class, choose that."""
        api = _make_mock_api_list_ingress_class(ONE_INGRESS_CLASS_LIST)
        body = self.harness.charm._get_k8s_ingress()
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertEqual(body.spec.ingress_class_name, 'public')

    def test_two_ingress_classes(self):
        """If there are two ingress classes, one default, choose that."""
        api = _make_mock_api_list_ingress_class(TWO_INGRESS_CLASSES_LIST)
        body = self.harness.charm._get_k8s_ingress()
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertEqual(body.spec.ingress_class_name, 'public')

    def test_two_ingress_classes_two_default(self):
        """If there are two ingress classes, both default, choose neither."""
        api = _make_mock_api_list_ingress_class(TWO_INGRESS_CLASSES_LIST_TWO_DEFAULT)
        body = self.harness.charm._get_k8s_ingress()
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertIsNone(body.spec.ingress_class_name)
