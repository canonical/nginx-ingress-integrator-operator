# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from unittest import mock
from unittest.mock import MagicMock, patch

import kubernetes
import kubernetes.client

from ops.model import (
    ActiveStatus,
    BlockedStatus,
)
from ops.testing import Harness
from charm import NginxIngressCharm
import pdb


class TestCharm(unittest.TestCase):
    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    def test_config_changed(
        self, _define_service, _define_ingress, _report_service_ips
    ):
        """Test our config changed handler."""
        # First of all test, with leader set to True.
        self.harness.set_leader(True)
        _report_service_ips.return_value = ["10.0.1.12"]
        # Confirm our _define_ingress and _define_service methods haven't been called.
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # Test if config-changed is called with service-hostname, service-name, service-port empty,
        # our methods still aren't called.
        self.harness.update_config({"service-name": ""})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        self.harness.update_config({"service-name": "gunicorn"})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        self.harness.update_config({"service-port": 80})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # And now test if we set a service-hostname config, our methods are called.
        self.harness.update_config({"service-hostname": "gunic.orn"})
        self.assertEqual(_define_ingress.call_count, 1)
        self.assertEqual(_define_service.call_count, 1)
        # Confirm status is as expected.
        self.assertEqual(
            self.harness.charm.unit.status,
            ActiveStatus("Ingress with service IP(s): 10.0.1.12"),
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
        _define_service.side_effect = kubernetes.client.exceptions.ApiException(
            status=403
        )
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
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_name, "")
        self.assertEqual(conf_or_rel._service_hostname, "")
        self.assertEqual(conf_or_rel._service_port, 0)
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        # And now confirm we have the expected data in the relevant properties.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_name, "gunicorn")
        self.assertEqual(conf_or_rel._service_hostname, "foo.internal")
        self.assertEqual(conf_or_rel._service_port, 80)

    def test_get_ingress_relation_data_ingress_relation_standard(self):
        """
        arrange: given charm that does not have a relation configured
        act: when a new relation is added with data based on the new ingress interface standard
        assert: then the relation data is saved correctly.
        """
        # Confirm we don't have any relation data yet in the relevant properties
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_name, "")
        self.assertEqual(conf_or_rel._service_hostname, "")
        self.assertEqual(conf_or_rel._service_port, 0)
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "name": "gunicorn",
            "host": "foo.internal",
            "port": "80",
            "model": "model 1",
        }

        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)

        # And now confirm we have the expected data in the relevant properties.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_name, "gunicorn")
        self.assertEqual(conf_or_rel._service_hostname, "foo.internal")
        self.assertEqual(conf_or_rel._service_port, 80)
        self.assertEqual(conf_or_rel._namespace, "model 1")

    def test_multiple_routes_with_relation_data(self):
        """Test for getting our ingress relation data."""
        # Confirm we don't have any relation data yet in the relevant properties
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
            "path-routes": "/admin/,/portal/",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)

        # Test multiple paths
        expected = [
            {
                "backend": {
                    "resource": None,
                    "service": {
                        "name": "gunicorn-service",
                        "port": {
                            "name": None,
                            "number": 80,
                        },
                    },
                },
                "path": "/admin/",
                "path_type": "Prefix",
            },
            {
                "backend": {
                    "resource": None,
                    "service": {
                        "name": "gunicorn-service",
                        "port": {
                            "name": None,
                            "number": 80,
                        },
                    },
                },
                "path": "/portal/",
                "path_type": "Prefix",
            },
        ]
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        result_dict = conf_or_rel._get_k8s_ingress().to_dict()
        self.assertEqual(result_dict["spec"]["rules"][0]["http"]["paths"], expected)

    def test_max_body_size(self):
        """Test for the max-body-size property."""
        # First set via config.
        self.harness.update_config({"max-body-size": 80})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._max_body_size, "80m")
        # Now set via the StoredState. This will be set to a string, as all
        # relation data must be a string.
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "max-body-size": "88",
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        # Still 80 because it's set via config.
        self.assertEqual(conf_or_rel._max_body_size, "80m")
        self.harness.update_config({"max-body-size": 0})
        # Now it's the value from the relation.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._max_body_size, "88m")

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
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
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
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        self.assertEqual(self.harness.charm._namespace, "relationnamespace")

    def test_owasp_modsecurity_crs(self):
        """Test the owasp-modsecurity-crs property."""
        # Test undefined.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._owasp_modsecurity_crs, False)
        # Test we have no annotations with this set to False.
        self.harness.disable_hooks()
        self.harness.update_config(
            {
                "service-hostname": "foo.internal",
                "service-name": "gunicorn",
                "service-port": 80,
            }
        )
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        result_dict = conf_or_rel._get_k8s_ingress().to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)
        # Test if we set the value we get the correct annotations and the
        # correct charm property.
        self.harness.update_config({"owasp-modsecurity-crs": True})
        self.assertEqual(conf_or_rel._owasp_modsecurity_crs, True)
        result_dict = conf_or_rel._get_k8s_ingress().to_dict()
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
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._retry_errors, "")
        # Test we deal with spaces or not spaces properly.
        self.harness.update_config(
            {"retry-errors": "error, timeout, http_502, http_503"}
        )
        self.assertEqual(conf_or_rel._retry_errors, "error timeout http_502 http_503")
        self.harness.update_config({"retry-errors": "error,timeout,http_502,http_503"})
        self.assertEqual(conf_or_rel._retry_errors, "error timeout http_502 http_503")
        # Test unknown value.
        self.harness.update_config({"retry-errors": "error,timeout,http_502,http_418"})
        self.assertEqual(conf_or_rel._retry_errors, "error timeout http_502")

    def test_service_port(self):
        """Test the service-port property."""
        # First set via config.
        self.harness.update_config({"service-port": 80})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_port, 80)
        # Now set via the relation.
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "88",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        # Config still overrides the relation value.
        self.assertEqual(conf_or_rel._service_port, 80)
        self.harness.update_config({"service-port": 0})
        # Now it's the value from the relation.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_port, 88)

    def test_service_hostname(self):
        """Test the service-hostname property."""
        # First set via config.
        self.harness.update_config({"service-hostname": "foo.internal"})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_hostname, "foo.internal")
        # Now set via the relation.
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo-bar.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        # Config still overrides the relation value.
        self.assertEqual(conf_or_rel._service_hostname, "foo.internal")
        self.harness.update_config({"service-hostname": ""})
        # Now it's the value from the relation.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_hostname, "foo-bar.internal")

    def test_session_cookie_max_age(self):
        """Test the session-cookie-max-age property."""
        # First set via config.
        self.harness.update_config({"session-cookie-max-age": 3600})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._session_cookie_max_age, "3600")
        # Confirm if we set this to 0 we get a False value, e.g. it doesn't
        # return a string of "0" which would be evaluated to True.
        self.harness.update_config({"session-cookie-max-age": 0})
        self.assertFalse(conf_or_rel._session_cookie_max_age)
        # Now set via the relation.
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
            "session-cookie-max-age": "3688",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._session_cookie_max_age, "3688")

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_services")
    def test_tls_secret_name(self, mock_def_svc, mock_def_ingress, mock_report_ips):
        """Test the tls-secret-name property."""
        mock_report_ips.return_value = ["10.0.1.12"]
        self.harness.update_config({"tls-secret-name": "gunicorn-tls"})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._tls_secret_name, "gunicorn-tls")
        # Now set via the relation.
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
            "tls-secret-name": "gunicorn-tls-new",
            "additional-hostnames": "lish.internal",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        # Config still overrides the relation data.
        self.assertEqual(conf_or_rel._tls_secret_name, "gunicorn-tls")

        # The charm will not create any resource if it's not the leader.
        # Check to see if the charm will use the TLS secret name for the additional hostname.
        self.harness.set_leader(True)
        self.harness.update_config({"tls-secret-name": ""})
        # Now it's the value from the relation.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._tls_secret_name, "gunicorn-tls-new")

        mock_def_svc.assert_called_once()
        base_ingress = conf_or_rel._get_k8s_ingress()

        tls_lish = kubernetes.client.V1IngressTLS(
            hosts=["lish.internal"],
            secret_name=base_ingress.spec.tls[0].secret_name,
        )
        ingress_lish = kubernetes.client.V1Ingress(
            api_version=base_ingress.api_version,
            kind=base_ingress.kind,
            metadata=kubernetes.client.V1ObjectMeta(
                name="lish-internal-ingress",
                annotations=base_ingress.metadata.annotations,
            ),
            spec=kubernetes.client.V1IngressSpec(
                tls=[tls_lish],
                rules=[
                    kubernetes.client.V1IngressRule(
                        host="lish.internal",
                        http=base_ingress.spec.rules[1].http,
                    )
                ],
            ),
        )

        # Since the hostnames are different, it's expected that 2 different Ingress Resources
        # are created. base_ingress contains the rules for both.
        base_ingress.spec.rules = [base_ingress.spec.rules[0]]

        mock_def_ingress.assert_has_calls(
            [
                mock.call(base_ingress),
                mock.call(ingress_lish),
            ]
        )

    def test_rewrite_enabled_property(self):
        """Test for enabling request rewrites."""
        # First set via config.
        self.harness.update_config({"rewrite-enabled": True})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._rewrite_enabled, True)
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "rewrite-enabled": "False",
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        # Still /test-target because it's set via config.
        self.assertEqual(conf_or_rel._rewrite_enabled, True)
        self.harness.update_config({"rewrite-enabled": ""})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._rewrite_enabled, False)

    def test_rewrite_annotations(self):
        self.harness.disable_hooks()
        self.harness.update_config(
            {
                "service-hostname": "foo.internal",
                "service-name": "gunicorn",
                "service-port": 80,
            }
        )
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        result_dict = conf_or_rel._get_k8s_ingress().to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

        self.harness.update_config({"rewrite-enabled": False})
        result_dict = conf_or_rel._get_k8s_ingress().to_dict()
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
        result_dict = conf_or_rel._get_k8s_ingress().to_dict()
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

    @patch("charm.NginxIngressCharm._on_config_changed")
    def test_on_ingress_relation_changed(self, _on_config_changed):
        """Test ingress relation changed handler."""
        # Confirm we do nothing if we're not the leader.
        self.assertFalse(self.harness.charm.unit.is_leader())
        # Confirm config_changed hasn't been called.
        _on_config_changed.assert_not_called()

        # Now test on the leader, but with missing fields in the relation data.
        # We don't want leader-set to fire.
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
        }
        with self.assertLogs(level="ERROR") as logger:
            self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
            msg = (
                "ERROR:charms.nginx_ingress_integrator.v0.ingress:Missing required data fields "
                "for ingress relation: service-hostname, service-port"
            )
            self.assertEqual(sorted(logger.output), [msg])
            # Confirm blocked status.
            self.assertEqual(
                self.harness.charm.unit.status,
                BlockedStatus(
                    "Missing fields for ingress: service-hostname, service-port"
                ),
            )

        # Now test with complete relation data.
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        # Test we get the values we expect:
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._service_hostname, "foo.internal")
        self.assertEqual(conf_or_rel._service_name, "gunicorn")
        self.assertEqual(conf_or_rel._service_port, 80)

    @patch("charm.NginxIngressCharm._remove_ingress")
    @patch("charm.NginxIngressCharm._remove_service")
    def test_on_ingress_relation_broken_unauthorized(
        self, _remove_service, _remove_ingress
    ):
        """Test the Unauthorized case on relation-broken."""
        # Call the test test_on_ingress_relation_changed first
        # to make sure the relation is created and therefore can be removed.
        self.test_on_ingress_relation_changed()
        _remove_service.side_effect = kubernetes.client.exceptions.ApiException(
            status=403
        )

        self.harness.charm._authed = True
        relation = self.harness.charm.model.get_relation("ingress")
        self.harness.remove_relation(relation.id)

        expected_status = BlockedStatus(
            "Insufficient permissions, try: `juju trust %s --scope=cluster`"
            % self.harness.charm.app.name
        )
        self.assertEqual(self.harness.charm.unit.status, expected_status)

    @patch("charm._networking_v1_api")
    @patch("charm._core_v1_api")
    def test_on_ingress_relation_broken(self, mock_core_api, mock_net_api):
        """Test relation-broken."""
        # Call the test test_on_ingress_relation_changed first
        # to make sure the relation is created and therefore can be removed.
        self.test_on_ingress_relation_changed()

        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_service = mock.Mock()
        mock_service.metadata.name = conf_or_rels[0]._service_name
        mock_services = mock_core_api.return_value.list_namespaced_service.return_value
        mock_services.items = [mock_service]

        mock_ingress = mock.Mock()
        mock_ingress.metadata.name = conf_or_rels[0]._ingress_name
        mock_ingresses = mock_net_api.return_value.list_namespaced_ingress.return_value
        mock_ingresses.items = [mock_ingress]

        self.harness.charm._authed = True
        relation = self.harness.charm.model.get_relation("ingress")
        self.harness.remove_relation(relation.id)

        mock_core_api.delete_namespaced_service(
            name=conf_or_rels[0]._service_name, namespace=conf_or_rels[0]._namespace
        )
        mock_net_api.delete_namespaced_ingress(
            conf_or_rels[0]._ingress_name, conf_or_rels[0]._namespace
        )

    def test_get_k8s_ingress(self):
        """Test getting our definition of a k8s ingress."""
        self.harness.disable_hooks()
        self.harness.update_config(
            {
                "service-hostname": "foo.internal",
                "service-name": "gunicorn",
                "service-port": 80,
            }
        )
        expected_ingress_name = "foo-internal-ingress"
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=expected_ingress_name,
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
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._get_k8s_ingress(), expected)
        # Test additional hostnames
        self.harness.update_config(
            {"additional-hostnames": "bar.internal,foo.external"}
        )
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=expected_ingress_name,
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(), expected)
        self.harness.update_config({"additional-hostnames": ""})
        # Test multiple paths
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=expected_ingress_name,
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(), expected)
        self.harness.update_config({"path-routes": "/"})
        # Test with TLS.
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=expected_ingress_name,
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(), expected)
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
                name=expected_ingress_name,
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(), expected)
        # Test limit-whitelist on its own makes no change.
        self.harness.update_config({"limit-whitelist": "10.0.0.0/16"})
        self.assertEqual(conf_or_rel._get_k8s_ingress(), expected)
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
                name=expected_ingress_name,
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(), expected)

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
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._get_k8s_service(), expected)


INGRESS_CLASS_PUBLIC_DEFAULT = kubernetes.client.V1beta1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={
            "ingressclass.kubernetes.io/is-default-class": "true",
        },
        name="public",
    ),
    spec=kubernetes.client.V1beta1IngressClassSpec(
        controller="k8s.io/ingress-nginx",
    ),
)

INGRESS_CLASS_PRIVATE = kubernetes.client.V1beta1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={},
        name="private",
    ),
    spec=kubernetes.client.V1beta1IngressClassSpec(
        controller="k8s.io/ingress-nginx",
    ),
)

INGRESS_CLASS_PRIVATE_DEFAULT = kubernetes.client.V1beta1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={
            "ingressclass.kubernetes.io/is-default-class": "true",
        },
        name="private",
    ),
    spec=kubernetes.client.V1beta1IngressClassSpec(
        controller="k8s.io/ingress-nginx",
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
            {
                "service-hostname": "foo.internal",
                "service-name": "gunicorn",
                "service-port": 80,
            }
        )

    def test_zero_ingress_class(self):
        """If there are no ingress classes, there's nothing to choose from."""
        api = _make_mock_api_list_ingress_class(ZERO_INGRESS_CLASS_LIST)
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        body = conf_or_rel._get_k8s_ingress()
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertIsNone(body.spec.ingress_class_name)

    def test_one_ingress_class(self):
        """If there's one default ingress class, choose that."""
        api = _make_mock_api_list_ingress_class(ONE_INGRESS_CLASS_LIST)
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        body = conf_or_rel._get_k8s_ingress()
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertEqual(body.spec.ingress_class_name, "public")

    def test_two_ingress_classes(self):
        """If there are two ingress classes, one default, choose that."""
        api = _make_mock_api_list_ingress_class(TWO_INGRESS_CLASSES_LIST)
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        body = conf_or_rel._get_k8s_ingress()
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertEqual(body.spec.ingress_class_name, "public")

    def test_two_ingress_classes_two_default(self):
        """If there are two ingress classes, both default, choose neither."""
        api = _make_mock_api_list_ingress_class(TWO_INGRESS_CLASSES_LIST_TWO_DEFAULT)
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        body = conf_or_rel._get_k8s_ingress()
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertIsNone(body.spec.ingress_class_name)


class TestCharmMultipleRelations(unittest.TestCase):
    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def _add_ingress_relation(self, relator_name, rel_data):
        relation_id = self.harness.add_relation("ingress", relator_name)
        self.harness.add_relation_unit(relation_id, "%s/0" % relator_name)

        self.harness.update_relation_data(relation_id, relator_name, rel_data)
        return relation_id

    def test_get_multiple_ingress_relation_data(self):
        """Test for getting our multiple ingress relation data."""
        # Confirm we don't have any relation data yet in the relevant properties
        # NOTE: _all_config_or_relations will always have at least one element.
        conf_or_rels = self.harness.charm._all_config_or_relations
        self.assertEqual(0, len(self.harness.charm.model.relations["ingress"]))
        self.assertEqual(1, len(conf_or_rels))

        self.assertEqual(conf_or_rels[0]._service_name, "")
        self.assertEqual(conf_or_rels[0]._service_hostname, "")
        self.assertEqual(conf_or_rels[0]._service_port, 0)

        # Add the first relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
            "path-routes": "/gunicorn",
        }
        rel_id1 = self._add_ingress_relation("gunicorn", rel_data)

        # Add another relation with the same hostname.
        rel_data = {
            "service-name": "funicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "8080",
        }
        rel_id2 = self._add_ingress_relation("funicorn", rel_data)

        # And now, confirm we have 2 relations and their respective data, and that the expected
        # data is in the relevant properties.
        conf_or_rels = self.harness.charm._all_config_or_relations
        self.assertEqual(2, len(self.harness.charm.model.relations["ingress"]))
        self.assertEqual(2, len(conf_or_rels))

        self.assertEqual(conf_or_rels[0]._service_name, "gunicorn")
        self.assertEqual(conf_or_rels[0]._service_hostname, "foo.in.ternal")
        self.assertEqual(conf_or_rels[0]._service_port, 80)

        self.assertEqual(conf_or_rels[1]._service_name, "funicorn")
        self.assertEqual(conf_or_rels[1]._service_hostname, "foo.in.ternal")
        self.assertEqual(conf_or_rels[1]._service_port, 8080)

        # Update the service hostname config option and expect it to be used instead of the
        # service hostname set in the relations (config options have precedence over relations)
        self.harness.update_config({"service-hostname": "lish.internal"})
        conf_or_rels = self.harness.charm._all_config_or_relations
        self.assertEqual(conf_or_rels[0]._service_hostname, "lish.internal")
        self.assertEqual(conf_or_rels[1]._service_hostname, "lish.internal")

        # Reset the service hostname config option and expect that the original service hostnames
        # are used instead.
        self.harness.update_config({"service-hostname": ""})
        conf_or_rels = self.harness.charm._all_config_or_relations
        self.assertEqual(conf_or_rels[0]._service_hostname, "foo.in.ternal")
        self.assertEqual(conf_or_rels[1]._service_hostname, "foo.in.ternal")

        # Check that the service name, service port, and path routes come from relation data,
        # not config options.
        self.harness.update_config(
            {
                "service-name": "foo",
                "service-port": "1111",
                "path-routes": "/foo",
            }
        )

        conf_or_rels = self.harness.charm._all_config_or_relations
        self.assertEqual(conf_or_rels[0]._service_name, "gunicorn")
        self.assertEqual(conf_or_rels[0]._service_port, 80)
        self.assertEqual(conf_or_rels[0]._path_routes, ["/gunicorn"])

        # Remove the relations and assert that there are no relations to be found.
        self.harness.remove_relation(rel_id1)
        self.harness.remove_relation(rel_id2)

        self.assertEqual(0, len(self.harness.charm.model.relations["ingress"]))

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._remove_ingress")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm._core_v1_api")
    def test_services_for_multiple_relations(
        self, mock_api, mock_define_ingress, mock_remove_ingress, mock_report_ips
    ):
        """Test for checking Service creation / deletion for multiple relations."""
        # Setting the leader to True will allow us to test the Service creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_list_services = mock_api.return_value.list_namespaced_service
        # We'll consider we don't have any service set yet.
        mock_list_services.return_value.items = []

        # Add the first relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
        }
        self._add_ingress_relation("gunicorn", rel_data)

        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_create_service = mock_api.return_value.create_namespaced_service
        mock_create_service.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[0]._get_k8s_service(),
        )

        # Reset the create service mock, and add a second relation. Expect the first service to
        # be updated, and the second one to be created.
        mock_create_service.reset_mock()
        mock_service1 = MagicMock()
        mock_service1.metadata.name = "gunicorn-service"
        mock_list_services.return_value.items = [mock_service1]

        rel_data = {
            "service-name": "funicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "8080",
        }
        self._add_ingress_relation("funicorn", rel_data)

        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_patch_service = mock_api.return_value.patch_namespaced_service
        mock_patch_service.assert_called_once_with(
            name=conf_or_rels[0]._k8s_service_name,
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[0]._get_k8s_service(),
        )
        mock_create_service.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[1]._get_k8s_service(),
        )

        # Remove the first relation and assert that only the first service is removed.
        mock_service2 = MagicMock()
        mock_service2.metadata.name = "funicorn-service"
        mock_list_services.return_value.items = [mock_service1, mock_service2]

        relation = self.harness.charm.model.relations["ingress"][0]
        self.harness.charm.on.ingress_relation_broken.emit(relation)

        mock_delete_service = mock_api.return_value.delete_namespaced_service
        mock_delete_service.assert_called_once_with(
            name=conf_or_rels[0]._k8s_service_name,
            namespace=self.harness.charm._namespace,
        )

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._remove_service")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm._networking_v1_api")
    def test_ingresses_for_multiple_relations_same_hostname(
        self, mock_api, mock_define_service, mock_remove_service, mock_report_ips
    ):
        """Test for checking Ingress creation / deletion for multiple relations.

        This test will check that the charm will not create multiple Resources for the same
        hostname, and that it won't remove the resource if there's still an active relation
        using it.
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_list_ingress = mock_api.return_value.list_namespaced_ingress
        # We'll consider we don't have any ingresses set yet.
        mock_list_ingress.return_value.items = []

        # Add the first relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
        }
        rel_id1 = self._add_ingress_relation("gunicorn", rel_data)

        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_create_ingress = mock_api.return_value.create_namespaced_ingress

        # Since we only have one relation, the merged ingress rule should be the same as before
        # the merge.
        mock_create_ingress.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[0]._get_k8s_ingress(),
        )

        # Reset the create ingress mock, and add a second relation.
        mock_create_ingress.reset_mock()
        mock_ingress1 = MagicMock()
        mock_ingress1.metadata.name = "foo-in-ternal-ingress"
        mock_list_ingress.return_value.items = [mock_ingress1]

        rel_data = {
            "service-name": "funicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "8080",
            # Since it has the same service-hostname as gunicorn, we need a different route.
            "path-routes": "/funicorn",
        }
        rel_id2 = self._add_ingress_relation("funicorn", rel_data)

        # We're expecting that the K8s Ingress Resource will be replaced by one that contains
        # paths from both relations. A new one should not have been created.
        mock_create_ingress.assert_not_called()

        conf_or_rels = self.harness.charm._all_config_or_relations
        expected_body = conf_or_rels[0]._get_k8s_ingress()
        second_body = conf_or_rels[1]._get_k8s_ingress()

        expected_body.spec.rules[0].http.paths.extend(
            second_body.spec.rules[0].http.paths
        )
        mock_replace_ingress = mock_api.return_value.replace_namespaced_ingress
        mock_replace_ingress.assert_called_once_with(
            name=conf_or_rels[0]._ingress_name,
            namespace=self.harness.charm._namespace,
            body=expected_body,
        )

        # Remove the first relation and assert that the Kubernetes Ingress Resource was updated
        # and not removed.
        mock_create_ingress.reset_mock()
        mock_replace_ingress.reset_mock()

        self.harness.remove_relation(rel_id1)

        # Assert that the ingress was replaced, not deleted (we still have a relation).
        mock_delete_ingress = mock_api.return_value.delete_namespaced_ingress
        mock_delete_ingress.assert_not_called()

        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_replace_ingress.assert_called_once_with(
            name=conf_or_rels[0]._ingress_name,
            namespace=self.harness.charm._namespace,
            body=second_body,
        )

        # Remove the second relation. This should cause the K8s Ingress Resource to be removed,
        # since we no longer have any relations needing it.
        mock_replace_ingress.reset_mock()
        mock_delete_ingress.reset_mock()
        self.harness.remove_relation(rel_id2)

        mock_create_ingress.assert_not_called()
        mock_replace_ingress.assert_not_called()
        mock_delete_ingress.assert_called_once_with(
            conf_or_rels[0]._ingress_name,
            self.harness.charm._namespace,
        )

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._remove_service")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm._networking_v1_api")
    def test_ingresses_for_multiple_relations_different_hostnames(
        self, mock_api, mock_define_service, mock_remove_service, mock_report_ips
    ):
        """Test for checking Ingress creation / deletion for multiple relations.

        This test will check that the charm will create multiple Resources for different hostnames.
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_list_ingress = mock_api.return_value.list_namespaced_ingress
        # We'll consider we don't have any ingresses set yet.
        mock_list_ingress.return_value.items = []

        # Add the first relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
        }
        rel_id1 = self._add_ingress_relation("gunicorn", rel_data)

        # Since we only have one relation, the merged ingress rule should be the same as before
        # the merge.
        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_create_ingress = mock_api.return_value.create_namespaced_ingress
        mock_create_ingress.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[0]._get_k8s_ingress(),
        )

        # Reset the create ingress mock, and add a second relation with a different
        # service-hostname. A different K8s Ingress Resource should be created.
        mock_create_ingress.reset_mock()
        mock_ingress1 = MagicMock()
        mock_ingress1.metadata.name = "foo-in-ternal-ingress"
        mock_list_ingress.return_value.items = [mock_ingress1]

        rel_data = {
            "service-name": "punicorn",
            "service-hostname": "lish.in.ternal",
            "service-port": "9090",
        }
        rel_id2 = self._add_ingress_relation("punicorn", rel_data)

        # We're expecting that the first K8s Ingress Resource will be updated, but it will not
        # change, and that a new K8s Ingress Resource will be created for the new relation,
        # since it has a different service-hostname.
        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_create_ingress.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[1]._get_k8s_ingress(),
        )
        mock_replace_ingress = mock_api.return_value.replace_namespaced_ingress
        mock_replace_ingress.assert_called_once_with(
            name=conf_or_rels[0]._ingress_name,
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[0]._get_k8s_ingress(),
        )

        # Remove the first relation and assert that only the first ingress is removed.
        mock_ingress2 = MagicMock()
        mock_ingress2.metadata.name = "lish-in-ternal-ingress"
        mock_list_ingress.return_value.items = [mock_ingress1, mock_ingress2]
        mock_create_ingress.reset_mock()
        mock_replace_ingress.reset_mock()
        self.harness.remove_relation(rel_id1)

        # Assert that only the ingress for the first relation was removed.
        mock_delete_ingress = mock_api.return_value.delete_namespaced_ingress
        mock_delete_ingress.assert_called_once_with(
            conf_or_rels[0]._ingress_name,
            self.harness.charm._namespace,
        )
        mock_create_ingress.assert_not_called()
        mock_replace_ingress.assert_called_once_with(
            name=conf_or_rels[1]._ingress_name,
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[1]._get_k8s_ingress(),
        )

        # Remove the second relation.
        mock_replace_ingress.reset_mock()
        mock_delete_ingress.reset_mock()
        self.harness.remove_relation(rel_id2)

        mock_delete_ingress.assert_called_once_with(
            conf_or_rels[1]._ingress_name,
            self.harness.charm._namespace,
        )
        mock_create_ingress.assert_not_called()
        mock_replace_ingress.assert_not_called()

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._remove_service")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm._networking_v1_api")
    def test_ingress_multiple_relations_additional_hostnames(
        self, mock_api, mock_define_service, mock_remove_service, mock_report_ips
    ):
        """Test for checking Ingress creation / deletion for multiple relations.

        This test will check that the charm will create multiple Resources for different hostnames.
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_list_ingress = mock_api.return_value.list_namespaced_ingress
        # We'll consider we don't have any ingresses set yet.
        mock_list_ingress.return_value.items = []

        # Add the first relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
            "additional-hostnames": "lish.in.ternal",
            "tls-secret-name": "some-secret",
        }
        rel_id1 = self._add_ingress_relation("gunicorn", rel_data)

        # It should create 2 different Ingress Resources, since we have an additional hostname.
        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_create_ingress = mock_api.return_value.create_namespaced_ingress
        first_body = conf_or_rels[0]._get_k8s_ingress()
        first_body.spec.rules = [first_body.spec.rules[0]]
        second_body = conf_or_rels[0]._get_k8s_ingress()
        second_body.metadata.name = "lish-in-ternal-ingress"
        second_body.spec.rules = [second_body.spec.rules[1]]
        second_body.spec.tls[0].hosts = ["lish.in.ternal"]
        mock_create_ingress.assert_has_calls(
            [
                mock.call(namespace=self.harness.charm._namespace, body=first_body),
                mock.call(namespace=self.harness.charm._namespace, body=second_body),
            ]
        )

        # Reset the create ingress mock, and add a second relation with the service-hostname set
        # to the first relation's additional-hostname. A third K8s Ingress Resource should not
        # be created.
        mock_create_ingress.reset_mock()
        mock_ingress1 = MagicMock()
        mock_ingress1.metadata.name = "foo-in-ternal-ingress"
        mock_ingress2 = MagicMock()
        mock_ingress2.metadata.name = "lish-in-ternal-ingress"
        mock_list_ingress.return_value.items = [mock_ingress1, mock_ingress2]

        rel_data = {
            "service-name": "punicorn",
            "service-hostname": "lish.in.ternal",
            "service-port": "9090",
            "path-routes": "/lish",
            "tls-secret-name": "some-secret",
        }
        self._add_ingress_relation("punicorn", rel_data)

        # We're expecting that the first K8s Ingress Resource will be updated, but it will not
        # change, and that the second K8s Ingress Resource will be updated to include the route
        # from the second relation.
        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_create_ingress.assert_not_called()

        second_rel_body = conf_or_rels[1]._get_k8s_ingress()
        second_body.spec.rules[0].http.paths.extend(
            second_rel_body.spec.rules[0].http.paths
        )
        calls = [
            mock.call(
                name=conf_or_rels[0]._ingress_name,
                namespace=self.harness.charm._namespace,
                body=first_body,
            ),
            mock.call(
                name=conf_or_rels[1]._ingress_name,
                namespace=self.harness.charm._namespace,
                body=second_body,
            ),
        ]
        mock_replace_ingress = mock_api.return_value.replace_namespaced_ingress
        mock_replace_ingress.assert_has_calls(calls)

        # Remove the first relation and assert that only the first ingress is removed.
        mock_ingress2 = MagicMock()
        mock_ingress2.metadata.name = "lish-in-ternal-ingress"
        mock_list_ingress.return_value.items = [mock_ingress1, mock_ingress2]
        mock_create_ingress.reset_mock()
        mock_replace_ingress.reset_mock()
        self.harness.remove_relation(rel_id1)

        # Assert that only the ingress for the first relation was removed.
        mock_delete_ingress = mock_api.return_value.delete_namespaced_ingress
        mock_delete_ingress.assert_called_once_with(
            conf_or_rels[0]._ingress_name,
            self.harness.charm._namespace,
        )
        mock_create_ingress.assert_not_called()
        mock_replace_ingress.assert_called_once_with(
            name=conf_or_rels[1]._ingress_name,
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[1]._get_k8s_ingress(),
        )

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm._networking_v1_api")
    def test_ingresses_for_multiple_relations_blocked(
        self, mock_api, mock_define_service, mock_define_ingress, mock_report_ips
    ):
        """Test for checking the Blocked cases for multiple relations."""
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_list_ingress = mock_api.return_value.list_namespaced_ingress
        # We'll consider we don't have any ingresses set yet.
        mock_list_ingress.return_value.items = []

        # Add the first relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
        }
        self._add_ingress_relation("gunicorn", rel_data)

        # Add the second relation. It will have the same service-hostname as the first relation.
        # It will also have a conflicting annotation, and conflicting route "/", which will cause
        # the relation to become Blocked.
        rel_data = {
            "service-name": "funicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "9090",
            "retry-errors": "error,timeout",
        }
        rel_id = self._add_ingress_relation("funicorn", rel_data)

        expected_status = BlockedStatus(
            "Conflicting annotations from relations. Run juju debug-log for details. "
            "Set manually via juju config."
        )
        self.assertEqual(expected_status, self.harness.charm.unit.status)

        # Override the rewrite target through the config option. It should fix the problem.
        self.harness.update_config({"retry-errors": "error,timeout"})

        # We still have the issue with the duplicate route.
        expected_status = BlockedStatus(
            "Duplicate route found; cannot add ingress. Run juju debug-log for details."
        )
        self.assertEqual(expected_status, self.harness.charm.unit.status)

        # Update the relation data to have a different route.
        rel_data["path-routes"] = "/funicorn"
        self.harness.update_relation_data(rel_id, "funicorn", rel_data)

        expected_status = ActiveStatus("Ingress with service IP(s): 10.0.1.12")
        self.assertEqual(expected_status, self.harness.charm.unit.status)

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    def test_missing_relation_data(
        self, mock_define_service, mock_define_ingress, mock_report_ips
    ):
        """Test for handling missing relation data."""
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)

        mock_report_ips.return_value = ["10.0.1.12"]

        # Add the first relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
        }
        self._add_ingress_relation("gunicorn", rel_data)

        # Add the second relation, but it will not have any relation data. No services or
        # ingresses should be defined for it.
        mock_define_service.reset_mock()
        mock_define_ingress.reset_mock()
        rel_id = self._add_ingress_relation("funicorn", {})

        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_define_service.assert_not_called()
        mock_define_ingress.assert_not_called()

        # Update the relation data to container proper data.
        mock_define_service.reset_mock()
        mock_define_ingress.reset_mock()
        rel_data = {
            "service-name": "funicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
            # Since it has the same service-hostname as gunicorn, we need a different route.
            "path-routes": "/funicorn",
        }
        self.harness.update_relation_data(rel_id, "funicorn", rel_data)

        conf_or_rels = self.harness.charm._all_config_or_relations
        mock_define_service.assert_has_calls([mock.call(mock.ANY), mock.call(mock.ANY)])
        second_body = conf_or_rels[1]._get_k8s_ingress()
        expected_body = conf_or_rels[0]._get_k8s_ingress()
        expected_body.spec.rules[0].http.paths.extend(
            second_body.spec.rules[0].http.paths
        )
        mock_define_ingress.assert_called_once_with(expected_body)
