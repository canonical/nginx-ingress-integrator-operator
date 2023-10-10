# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest import mock
from unittest.mock import MagicMock, patch

import kubernetes
import kubernetes.client
import pytest
from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateAvailableEvent,
    CertificateInvalidatedEvent,
)
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus
from ops.testing import Harness

from charm import (
    CREATED_BY_LABEL,
    INVALID_BACKEND_PROTOCOL_MSG,
    INVALID_HOSTNAME_MSG,
    ConflictingAnnotationsError,
    ConflictingRoutesError,
    InvalidBackendProtocolError,
    InvalidHostnameError,
    NginxIngressCharm,
)
from helpers import generate_password, invalid_hostname_check


class TestCharm(unittest.TestCase):
    """Class for charm testing."""

    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_start(self):
        """
        arrange: when the charm is first initialised
        act: we then run the start hook
        assert: we change from Maintenance to Active status
        """
        self.assertEqual(self.harness.charm.unit.status, MaintenanceStatus())
        self.harness.charm.on.start.emit()
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())

    @patch("charm.NginxIngressCharm._delete_unused_ingresses")
    @patch("charm.NginxIngressCharm._delete_unused_services")
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    def test_config_changed(
        self,
        _define_service,
        _define_ingress,
        _report_service_ips,
        _report_ingress_ips,
        _delete_unused_services,
        _delete_unused_ingresses,
    ):
        """
        arrange: given the harnessed charm
        act: when we change the service name, port and hostname config
        assert: _define_ingress and define_service are only called when changing
        the hostname to a non-empty string, and the status message is appropriate.
        """
        # First of all test, with leader set to True.
        self.harness.set_leader(True)
        _report_ingress_ips.return_value = ["10.0.1.12"]
        _report_service_ips.return_value = ["10.0.1.13"]
        # Confirm our _define_ingress and _define_service methods haven't been called.
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        self.assertEqual(_delete_unused_services.call_count, 0)
        self.assertEqual(_delete_unused_ingresses.call_count, 0)
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
        # _delete_unused_services and _delete_unused_ingresses should be called
        # every time that the configuration is updated to a valid value
        self.assertEqual(_delete_unused_services.call_count, 3)
        self.assertEqual(_delete_unused_ingresses.call_count, 3)
        # Confirm status is as expected.
        self.assertTrue(
            self.harness.charm.unit.status,
            ActiveStatus("Ingress IP(s): 10.0.1.12, Service IP(s): 10.0.1.13"),
        )
        # Confirm version is set correctly
        self.assertEqual(
            self.harness.get_workload_version(),
            self.harness.charm._get_kubernetes_library_version(),
        )
        # And now test with leader is False.
        _define_ingress.reset_mock()
        _define_service.reset_mock()
        _delete_unused_services.reset_mock()
        _delete_unused_ingresses.reset_mock()
        self.harness.set_leader(False)
        self.harness.update_config({"service-name": ""})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # Leader False, but service-name defined should still do nothing.
        self.harness.update_config({"service-name": "gunicorn"})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        self.assertEqual(_delete_unused_services.call_count, 0)
        self.assertEqual(_delete_unused_ingresses.call_count, 0)
        # Confirm status is as expected.
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())
        # Confirm version is set correctly
        self.assertEqual(
            self.harness.get_workload_version(),
            self.harness.charm._get_kubernetes_library_version(),
        )

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
        result_dict = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name).to_dict()
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

    def test_backend_protocol(self):
        """Test for the backend-protocol property."""
        # First set via config.
        self.harness.update_config({"backend-protocol": "AJP"})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._backend_protocol, "AJP")
        # Now set via the StoredState. This will be set to a string, as all
        # relation data must be a string.
        relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(relation_id, "gunicorn/0")
        relations_data = {
            "backend-protocol": "HTTP",
            "service-name": "gunicorn",
            "service-hostname": "foo.internal",
            "service-port": "80",
        }
        self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
        self.assertEqual(conf_or_rel._backend_protocol, "AJP")
        self.harness.update_config({"backend-protocol": ""})
        # Now it's the value from the relation.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._backend_protocol, "HTTP")

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
        """Test the owasp-modsecurity-crs and owasp-modsecurity-custom-rules properties."""
        # Test undefined.
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._owasp_modsecurity_crs, False)
        self.assertEqual(conf_or_rel._owasp_modsecurity_custom_rules, "")
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
        result_dict = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name).to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
            "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)
        # Test if we set the value we get the correct annotations and the
        # correct charm property.
        self.harness.update_config({"owasp-modsecurity-crs": True})
        custom_rule = (
            "SecAction "
            '"id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1"\n'
        )
        self.harness.update_config({"owasp-modsecurity-custom-rules": custom_rule})
        self.assertEqual(conf_or_rel._owasp_modsecurity_crs, True)
        self.assertEqual(conf_or_rel._owasp_modsecurity_custom_rules, custom_rule)
        result_dict = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name).to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/enable-modsecurity": "true",
            "nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs": "true",
            "nginx.ingress.kubernetes.io/modsecurity-snippet": (
                "SecRuleEngine On\nSecAction"
                ' "id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1"\n'
                "\nInclude /etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf"
            ),
            "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
            "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

    def test_owasp_modsecurity_custom_rules_new_lines(self):
        r"""Test if new lines ('\n') in custom rules are correctly handled."""
        self.maxDiff = None
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.harness.update_config({"owasp-modsecurity-crs": True})
        custom_rule = (
            "SecAction "
            '"id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1"\n\n'
        )
        self.harness.update_config({"owasp-modsecurity-custom-rules": custom_rule})
        self.assertEqual(conf_or_rel._owasp_modsecurity_crs, True)
        self.assertEqual(conf_or_rel._owasp_modsecurity_custom_rules, custom_rule)
        result_dict = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name).to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/enable-modsecurity": "true",
            "nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs": "true",
            "nginx.ingress.kubernetes.io/modsecurity-snippet": (
                "SecRuleEngine On\nSecAction"
                ' "id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1"\n\n'
                "\nInclude /etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf"
            ),
            "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
            "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
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
        self.harness.update_config({"retry-errors": "error, timeout, http_502, http_503"})
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

    @patch("charm.NginxIngressCharm._core_v1_api")
    @patch("charm.NginxIngressCharm._remove_ingress")
    @patch("charm.NginxIngressCharm._delete_unused_ingresses")
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    def test_delete_unused_services(
        self,
        _define_service,
        _define_ingress,
        _report_service_ips,
        _report_ingress_ips,
        _delete_unused_ingresses,
        _remove_ingress,
        _core_v1_api,
    ):
        """
        arrange: existing service not used anymore
        act: set service-name by configuration
        assert: Status is active and delete_namespaced_service is called once with right parameter
        """
        self.harness.set_leader(True)
        _report_ingress_ips.return_value = ["10.0.1.12"]
        _report_service_ips.return_value = ["10.0.1.13"]
        self.harness.charm._authed = True
        mock_service = mock.Mock()
        mock_service.metadata.name = "to-be-removed"
        mock_services = _core_v1_api.return_value.list_namespaced_service.return_value
        mock_services.items = [mock_service]
        self.harness.update_config({"service-name": "foo"})
        self.assertTrue(
            self.harness.charm.unit.status,
            ActiveStatus("Ingress IP(s): 10.0.1.12, Service IP(s): 10.0.1.13"),
        )
        conf_or_rels = self.harness.charm._all_config_or_relations
        _core_v1_api.return_value.delete_namespaced_service.assert_called_once_with(
            name="to-be-removed", namespace=conf_or_rels[0]._namespace
        )

    @patch("charm.NginxIngressCharm._networking_v1_api")
    @patch("charm.NginxIngressCharm._remove_ingress")
    @patch("charm.NginxIngressCharm._delete_unused_services")
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    def test_delete_unused_ingresses(
        self,
        _define_service,
        _define_ingress,
        _report_service_ips,
        _report_ingress_ips,
        _delete_unused_services,
        _remove_ingress,
        _networking_v1_api,
    ):
        """
        arrange: existing ingress not used anymore
        act: set service-hostname by configuration and no additional-hostnames
        assert: Status is active and _remove_ingress is called once with right parameter
        """
        self.harness.set_leader(True)
        _report_ingress_ips.return_value = ["10.0.1.12"]
        _report_service_ips.return_value = ["10.0.1.13"]
        self.harness.charm._authed = True
        self.harness.update_config({"service-name": "foo"})
        mock_ingress = mock.Mock()
        mock_ingress.spec.rules = [
            kubernetes.client.V1IngressRule(
                host="to-be-removed.local",
            )
        ]
        mock_ingresses = _networking_v1_api.return_value.list_namespaced_ingress.return_value
        mock_ingresses.items = [mock_ingress]
        self.harness.update_config({"service-hostname": "foo.local"})
        self.assertTrue(
            self.harness.charm.unit.status,
            ActiveStatus("Ingress IP(s): 10.0.1.12, Service IP(s): 10.0.1.13"),
        )
        expected = self.harness.charm._ingress_name("to-be-removed.local")
        _remove_ingress.assert_called_once_with(expected)

    @patch("charm.NginxIngressCharm.k8s_auth")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    @patch("charm.NginxIngressCharm._remove_ingress")
    @patch("charm.NginxIngressCharm._delete_unused_services")
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    def test_delete_unused_ingresses_additional_hostnames(
        self,
        _define_service,
        _define_ingress,
        _report_service_ips,
        _report_ingress_ips,
        _delete_unused_services,
        _remove_ingress,
        _networking_v1_api,
        k8s_auth,
    ):
        """
        arrange: existing ingress not used anymore
        act: set service-hostname by configuration and set additional-hostnames
        assert: Status is active and _remove_ingress is called once with right parameter
        """
        self.harness.set_leader(True)
        _report_ingress_ips.return_value = ["10.0.1.12"]
        _report_service_ips.return_value = ["10.0.1.13"]
        self.harness.charm._authed = True
        self.harness.update_config({"service-name": "foo"})
        self.harness.update_config({"additional-hostnames": "some-host1.local,some-host2.local"})
        mock_ingress = mock.Mock()
        mock_ingress.spec.rules = [
            kubernetes.client.V1IngressRule(
                host="to-be-removed.local",
            )
        ]
        mock_ingress_additional1 = mock.Mock()
        mock_ingress_additional1.spec.rules = [
            kubernetes.client.V1IngressRule(
                host="some-host1.local",
            )
        ]
        mock_ingress_additional2 = mock.Mock()
        mock_ingress_additional2.spec.rules = [
            kubernetes.client.V1IngressRule(
                host="some-host2.local",
            )
        ]
        mock_items = MagicMock()
        mock_items.items = [mock_ingress, mock_ingress_additional1, mock_ingress_additional2]
        _networking_v1_api.return_value.list_namespaced_ingress.return_value = mock_items
        self.harness.update_config({"service-hostname": "foo.local"})
        self.assertTrue(
            self.harness.charm.unit.status,
            ActiveStatus("Ingress IP(s): 10.0.1.12, Service IP(s): 10.0.1.13"),
        )
        expected = self.harness.charm._ingress_name("to-be-removed.local")
        _remove_ingress.assert_called_once_with(expected)

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

    @patch("charm.NginxIngressCharm._delete_unused_ingresses", autospec=True)
    @patch("charm.NginxIngressCharm._delete_unused_services", autospec=True)
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_services")
    def test_tls_secret_name(
        self,
        mock_def_svc,
        mock_def_ingress,
        mock_report_ips,
        mock_ingress_ips,
        _delete_unused_ingresses,
        _delete_unused_services,
    ):
        """
        arrange: given the harnessed charm
        act: when we change the tls-secret-name property
        assert: tls-secret-property is now on all_config_and_relations,
        and works properly with the components/specs that need it.
        """
        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""
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
        base_ingress = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name)

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
                labels={CREATED_BY_LABEL: self.harness.charm.app.name},
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
        self.harness.update_config({"rewrite-enabled": False})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._rewrite_enabled, False)

    def test_whitelist_source_range(self):
        self.harness.update_config({"whitelist-source-range": "10.0.0.0/24,172.10.0.1"})
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        self.assertEqual(conf_or_rel._whitelist_source_range, "10.0.0.0/24,172.10.0.1")
        result_dict = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name).to_dict()
        self.assertEqual(
            result_dict["metadata"]["annotations"][
                "nginx.ingress.kubernetes.io/whitelist-source-range"
            ],
            "10.0.0.0/24,172.10.0.1",
        )

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
        result_dict = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name).to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
            "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

        self.harness.update_config({"rewrite-enabled": False})
        result_dict = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name).to_dict()
        expected = {
            "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
            "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        self.assertEqual(result_dict["metadata"]["annotations"], expected)

        self.harness.update_config({"rewrite-target": "/test-target"})
        self.harness.update_config({"rewrite-enabled": True})

        expected = {
            "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
            "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
            "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
            "nginx.ingress.kubernetes.io/rewrite-target": "/test-target",
            "nginx.ingress.kubernetes.io/ssl-redirect": "false",
        }
        result_dict = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name).to_dict()
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
        with self.assertLogs(level="WARNING") as logger:
            self.harness.update_relation_data(relation_id, "gunicorn", relations_data)
            msg = (
                "WARNING:charms.nginx_ingress_integrator.v0.ingress:Missing required data fields "
                "for ingress relation: service-hostname, service-port"
            )
            self.assertEqual(sorted(logger.output), [msg])
            # Confirm blocked status.
            status = self.harness.charm.unit.status
            self.assertEqual(status.name, "blocked")
            self.assertIn(
                "Missing fields for ingress: service-hostname, service-port", status.message
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

    def _run_on_ingress_relation_broken_exception(self, exception, expected_status):
        """Test exceptions on relation-broken.

        Args:
            exception: exception to be raised in the relation broken handler.
            expected_status: expected unit status.
        """
        with patch(
            "charm.NginxIngressCharm._define_ingresses",
            side_effect=exception,
        ), patch("charm.NginxIngressCharm._delete_unused_services"):
            # Call the test test_on_ingress_relation_changed first
            # to make sure the relation is created and therefore can be removed.
            self.test_on_ingress_relation_changed()
            self.harness.charm._authed = True
            relation = self.harness.charm.model.get_relation("ingress")
            self.harness.remove_relation(relation.id)  # type: ignore[union-attr]
            self.assertEqual(self.harness.charm.unit.status, expected_status)

    def test_on_ingress_relation_broken_unauthorized(self):
        """Test unauthorized error on ingress relation broken"""
        self._run_on_ingress_relation_broken_exception(
            kubernetes.client.exceptions.ApiException(status=403),
            BlockedStatus(
                "Insufficient permissions, "
                "try: `juju trust nginx-ingress-integrator --scope=cluster`"
            ),
        )

    def test_on_ingress_relation_broken_conflict_annotation(self):
        """Test conflict annotation error on ingress relation broken"""
        self._run_on_ingress_relation_broken_exception(
            ConflictingAnnotationsError(),
            BlockedStatus(
                "Conflicting annotations from relations. Run juju debug-log for details. "
                "Set manually via juju config."
            ),
        )

    def test_on_ingress_relation_broken_conflict_routes(self):
        """Test conflict routes error on ingress relation broken"""
        self._run_on_ingress_relation_broken_exception(
            ConflictingRoutesError(),
            BlockedStatus(
                "Duplicate route found; cannot add ingress. Run juju debug-log for details."
            ),
        ),

    def test_on_ingress_relation_invalid_hostname(self):
        """Test invalid hostname error on ingress relation broken"""
        self._run_on_ingress_relation_broken_exception(
            InvalidHostnameError(),
            BlockedStatus(INVALID_HOSTNAME_MSG),
        )

    def test_on_ingress_relation_invalid_backend_protocol(self):
        """Test invalid backend protocol on ingress relation broken"""
        self._run_on_ingress_relation_broken_exception(
            InvalidBackendProtocolError(),
            BlockedStatus(INVALID_BACKEND_PROTOCOL_MSG),
        )

    @patch("charm.NginxIngressCharm._networking_v1_api")
    @patch("charm.NginxIngressCharm._core_v1_api")
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
        mock_ingress.spec.rules = [unittest.mock.MagicMock(host=conf_or_rels[0]._service_hostname)]
        mock_ingresses = mock_net_api.return_value.list_namespaced_ingress.return_value
        mock_ingresses.items = [mock_ingress]

        self.harness.charm._authed = True
        relation = self.harness.charm.model.get_relation("ingress")
        self.harness.remove_relation(relation.id)  # type: ignore[union-attr]

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
                    "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
                labels={CREATED_BY_LABEL: self.harness.charm.app.name},
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name), expected)
        # Test additional hostnames
        self.harness.update_config({"additional-hostnames": "bar.internal,foo.external"})
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=expected_ingress_name,
                annotations={
                    "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
                labels={CREATED_BY_LABEL: self.harness.charm.app.name},
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name), expected)
        self.harness.update_config({"additional-hostnames": ""})
        # Test multiple paths
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=expected_ingress_name,
                annotations={
                    "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
                labels={CREATED_BY_LABEL: self.harness.charm.app.name},
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name), expected)
        self.harness.update_config({"path-routes": "/"})
        # Test with TLS.
        expected = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=expected_ingress_name,
                annotations={
                    "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
                    "nginx.ingress.kubernetes.io/proxy-body-size": "20m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                },
                labels={CREATED_BY_LABEL: self.harness.charm.app.name},
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
                    kubernetes.client.V1IngressTLS(  # nosec: gunicorn_tls is not a secret
                        hosts=["foo.internal"],
                        secret_name="gunicorn_tls",
                    ),
                ],
            ),
        )
        self.harness.update_config({"tls-secret-name": "gunicorn_tls"})
        self.assertEqual(conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name), expected)
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
                    "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
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
                labels={CREATED_BY_LABEL: self.harness.charm.app.name},
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name), expected)
        # Test limit-whitelist on its own makes no change.
        self.harness.update_config({"limit-whitelist": "10.0.0.0/16"})
        self.assertEqual(conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name), expected)
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
                    "nginx.ingress.kubernetes.io/proxy-read-timeout": "60",
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
                    "nginx.ingress.kubernetes.io/proxy-body-size": "0m",
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
                labels={CREATED_BY_LABEL: self.harness.charm.app.name},
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
        self.assertEqual(conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name), expected)

    def test_get_k8s_service(self):
        """Test getting our definition of a k8s service."""
        self.harness.disable_hooks()
        self.harness.update_config({"service-name": "gunicorn", "service-port": 80})
        expected = kubernetes.client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=kubernetes.client.V1ObjectMeta(
                name="gunicorn-service", labels={CREATED_BY_LABEL: self.harness.charm.app.name}
            ),
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
        self.assertEqual(conf_or_rel._get_k8s_service(label=self.harness.charm.app.name), expected)


INGRESS_CLASS_PUBLIC_DEFAULT = kubernetes.client.V1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={
            "ingressclass.kubernetes.io/is-default-class": "true",
        },
        name="public",
    ),
    spec=kubernetes.client.V1IngressClassSpec(
        controller="k8s.io/ingress-nginx",
    ),
)

INGRESS_CLASS_PRIVATE = kubernetes.client.V1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={},
        name="private",
    ),
    spec=kubernetes.client.V1IngressClassSpec(
        controller="k8s.io/ingress-nginx",
    ),
)

INGRESS_CLASS_PRIVATE_DEFAULT = kubernetes.client.V1IngressClass(
    metadata=kubernetes.client.V1ObjectMeta(
        annotations={
            "ingressclass.kubernetes.io/is-default-class": "true",
        },
        name="private",
    ),
    spec=kubernetes.client.V1IngressClassSpec(
        controller="k8s.io/ingress-nginx",
    ),
)

ZERO_INGRESS_CLASS_LIST = kubernetes.client.V1IngressClassList(items=[])

ONE_INGRESS_CLASS_LIST = kubernetes.client.V1IngressClassList(
    items=[
        INGRESS_CLASS_PUBLIC_DEFAULT,
    ],
)

TWO_INGRESS_CLASSES_LIST = kubernetes.client.V1IngressClassList(
    items=[
        INGRESS_CLASS_PUBLIC_DEFAULT,
        INGRESS_CLASS_PRIVATE,
    ]
)

TWO_INGRESS_CLASSES_LIST_TWO_DEFAULT = kubernetes.client.V1IngressClassList(
    items=[
        INGRESS_CLASS_PUBLIC_DEFAULT,
        INGRESS_CLASS_PRIVATE_DEFAULT,
    ]
)


def _make_mock_api_list_ingress_class(return_value):
    """Mock a list of Ingress classes.

    Args:
        return_value: Value to return as part of the Ingress class API mock.

    Returns:
        Mock API that simulates the list_ingress_class method.
    """
    mock_api = MagicMock()
    mock_api.list_ingress_class.return_value = return_value
    return mock_api


class TestCharmLookUpAndSetIngressClass(unittest.TestCase):
    """Class for Ingress class testing."""

    def setUp(self):
        """Setup method for the class."""
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
        body = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name)
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertIsNone(body.spec.ingress_class_name)

    def test_one_ingress_class(self):
        """If there's one default ingress class, choose that."""
        api = _make_mock_api_list_ingress_class(ONE_INGRESS_CLASS_LIST)
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        body = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name)
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertEqual(body.spec.ingress_class_name, "public")

    def test_two_ingress_classes(self):
        """If there are two ingress classes, one default, choose that."""
        api = _make_mock_api_list_ingress_class(TWO_INGRESS_CLASSES_LIST)
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        body = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name)
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertEqual(body.spec.ingress_class_name, "public")

    def test_two_ingress_classes_two_default(self):
        """If there are two ingress classes, both default, choose neither."""
        api = _make_mock_api_list_ingress_class(TWO_INGRESS_CLASSES_LIST_TWO_DEFAULT)
        conf_or_rel = self.harness.charm._all_config_or_relations[0]
        body = conf_or_rel._get_k8s_ingress(label=self.harness.charm.app.name)
        self.harness.charm._look_up_and_set_ingress_class(api, body)
        self.assertIsNone(body.spec.ingress_class_name)


class TestCharmMultipleRelations(unittest.TestCase):
    """Class for multiple relations testing."""

    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def _add_ingress_relation(self, relator_name, rel_data):
        """Add an Ingress relation.

        Args:
            relator_name: Name of the charm to relate with Ingress
            rel_data: Relation data.

        Returns:
            The relation id.
        """
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
                "service-port": 1111,
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

    @patch("charm.NginxIngressCharm._delete_unused_ingresses", autospec=True)
    @patch("charm.NginxIngressCharm._delete_unused_services", autospec=True)
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._remove_ingress")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._core_v1_api")
    def test_services_for_multiple_relations(
        self,
        mock_core_api,
        mock_define_ingress,
        mock_remove_ingress,
        mock_report_ips,
        mock_ingress_ips,
        _delete_unused_services,
        _delete_unused_ingresses,
    ):
        """
        arrange: given the harnessed charm
        act: when we create/delete services for multiple relations
        assert: the process of creating/deleting the relations and services runs correctly.
        """
        # Setting the leader to True will allow us to test the Service creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""
        mock_list_services = mock_core_api.return_value.list_namespaced_service
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
        mock_create_service = mock_core_api.return_value.create_namespaced_service
        mock_create_service.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[0]._get_k8s_service(label=self.harness.charm.app.name),
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
        mock_patch_service = mock_core_api.return_value.patch_namespaced_service
        mock_patch_service.assert_called_once_with(
            name=conf_or_rels[0]._k8s_service_name,
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[0]._get_k8s_service(self.harness.charm.app.name),
        )
        mock_create_service.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=conf_or_rels[1]._get_k8s_service(self.harness.charm.app.name),
        )

        # Remove the first relation and assert that only the first service is removed.
        mock_service2 = MagicMock()
        mock_service2.metadata.name = "funicorn-service"
        mock_list_services.return_value.items = [mock_service1, mock_service2]

        relation = self.harness.charm.model.relations["ingress"][0]
        self.harness.charm.on.ingress_relation_broken.emit(relation)

        _delete_unused_ingresses.assert_called()
        _delete_unused_services.assert_called()

    @patch("charm.NginxIngressCharm._delete_unused_ingresses", autospec=True)
    @patch("charm.NginxIngressCharm._delete_unused_services", autospec=True)
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._remove_service")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    def test_ingresses_for_multiple_relations_same_hostname(
        self,
        mock_api,
        mock_define_service,
        mock_remove_service,
        mock_report_ips,
        mock_ingress_ips,
        _delete_unused_services,
        _delete_unused_ingresses,
    ):
        """
        arrange: given the harnessed charm
        act: when we create/delete ingresses for multiple relations
        assert: this test will check that the charm will not create multiple Resources for the same
        hostname, and that it won't remove the resource if there's still an active relation
        using it.
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""
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
        expected_body = conf_or_rels[0]._get_k8s_ingress(label=self.harness.charm.app.name)
        mock_create_ingress.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=expected_body,
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
        expected_body = conf_or_rels[0]._get_k8s_ingress(label=self.harness.charm.app.name)
        second_body = conf_or_rels[1]._get_k8s_ingress(label=self.harness.charm.app.name)

        expected_body.spec.rules[0].http.paths.extend(second_body.spec.rules[0].http.paths)
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
        _delete_unused_ingresses.assert_called()

    @patch("charm.NginxIngressCharm._delete_unused_ingresses", autospec=True)
    @patch("charm.NginxIngressCharm._delete_unused_services", autospec=True)
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._remove_service")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    def test_ingresses_for_multiple_relations_different_hostnames(
        self,
        mock_api,
        mock_define_service,
        mock_remove_service,
        mock_report_ips,
        mock_ingress_ips,
        _delete_unused_services,
        _delete_unused_ingresses,
    ):
        """
        arrange: given the harnessed charm
        act: when we create/delete ingresses for multiple relations
        assert: this test will check that the charm will not create multiple Resources for
        different hostnames, and that it won't remove the resource if there's still
        an active relation using it.
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""
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
        expected_body = conf_or_rels[0]._get_k8s_ingress(label=self.harness.charm.app.name)
        mock_create_ingress.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=expected_body,
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
        expected_body = conf_or_rels[1]._get_k8s_ingress(label=self.harness.charm.app.name)
        mock_create_ingress.assert_called_once_with(
            namespace=self.harness.charm._namespace,
            body=expected_body,
        )
        mock_replace_ingress = mock_api.return_value.replace_namespaced_ingress
        expected_body = conf_or_rels[0]._get_k8s_ingress(label=self.harness.charm.app.name)
        mock_replace_ingress.assert_called_once_with(
            name=conf_or_rels[0]._ingress_name,
            namespace=self.harness.charm._namespace,
            body=expected_body,
        )

        # Remove the first relation and assert that only the first ingress is removed.
        mock_ingress2 = MagicMock()
        mock_ingress2.metadata.name = "lish-in-ternal-ingress"
        mock_list_ingress.return_value.items = [mock_ingress1, mock_ingress2]
        mock_create_ingress.reset_mock()
        mock_replace_ingress.reset_mock()
        self.harness.remove_relation(rel_id1)

        _delete_unused_ingresses.assert_called()
        mock_create_ingress.assert_not_called()
        expected_body = conf_or_rels[1]._get_k8s_ingress(label=self.harness.charm.app.name)
        mock_replace_ingress.assert_called_once_with(
            name=conf_or_rels[1]._ingress_name,
            namespace=self.harness.charm._namespace,
            body=expected_body,
        )

        # Remove the second relation.
        mock_replace_ingress.reset_mock()
        _delete_unused_ingresses.reset_mock()
        self.harness.remove_relation(rel_id2)

        _delete_unused_ingresses.assert_called_once()
        mock_create_ingress.assert_not_called()
        mock_replace_ingress.assert_not_called()

    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm.k8s_auth")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._remove_service")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    def test_report_ingress_ips(
        self,
        mock_api,
        mock_define_service,
        mock_remove_service,
        mock_define_ingress,
        mock_k8s_auth,
        mock_service_ips,
    ):
        """
        arrange: given the harnessed charm
        act: when we execute report_ingress_ips()
        assert: this test will check that the charm will return an appropriate value if
        an ingress IP is found.
        """

        def get_item_lb(id):
            """Get a mock IP.

            Args:
                id: Auxiliary argument.

            Returns:
                localhost mock IP.
            """
            mock_ip = mock.Mock()
            mock_ip.ip = "127.0.0.1"
            return mock_ip

        mock_ingress = MagicMock()
        mock_ingress.status.load_balancer.ingress.__getitem__.side_effect = get_item_lb
        mock_items = MagicMock()
        mock_items.items = [mock_ingress]
        mock_api.return_value.list_namespaced_ingress.return_value = mock_items

        expected_result = ["127.0.0.1"]

        result = NginxIngressCharm._report_ingress_ips(NginxIngressCharm)  # type: ignore[arg-type]

        self.assertEqual(result, expected_result)

    @patch("charm._report_interval_count")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm.k8s_auth")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._remove_service")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    def test_report_ingress_ips_fail(
        self,
        mock_api,
        mock_define_service,
        mock_remove_service,
        mock_define_ingress,
        mock_k8s_auth,
        mock_service_ips,
        _report_interval_count,
    ):
        """
        arrange: given the harnessed charm
        act: when we execute report_ingress_ips()
        assert: this test will check that the charm will return a null value if
        an ingress IP is not found.
        """
        mock_items = MagicMock()
        mock_items.items = []
        mock_api.list_namespaced_ingress.return_value = mock_items

        expected_result: list = []

        _report_interval_count.return_value = 1

        result = NginxIngressCharm._report_ingress_ips(NginxIngressCharm)  # type: ignore[arg-type]

        self.assertEqual(result, expected_result)

    @patch("charm.NginxIngressCharm._delete_unused_ingresses", autospec=True)
    @patch("charm.NginxIngressCharm._delete_unused_services", autospec=True)
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._remove_service")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    def test_ingress_multiple_relations_additional_hostnames(
        self,
        mock_api,
        mock_define_service,
        mock_remove_service,
        mock_report_ips,
        mock_ingress_ips,
        _delete_unused_services,
        _delete_unused_ingresses,
    ):
        """
        arrange: given the harnessed charm
        act: when we create/delete ingresses for multiple relations
        assert: this test will check that the charm will create multiple Resources for additional
        hostnames, and that it won't remove the resource if there's still an active relation
        using it.
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""
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
        first_body = conf_or_rels[0]._get_k8s_ingress(label=self.harness.charm.app.name)
        first_body.spec.rules = [first_body.spec.rules[0]]
        second_body = conf_or_rels[0]._get_k8s_ingress(label=self.harness.charm.app.name)
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

        second_rel_body = conf_or_rels[1]._get_k8s_ingress(label=self.harness.charm.app.name)
        second_body.spec.rules[0].http.paths.extend(second_rel_body.spec.rules[0].http.paths)
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

        _delete_unused_ingresses.assert_called()
        mock_create_ingress.assert_not_called()
        expected_body = conf_or_rels[1]._get_k8s_ingress(label=self.harness.charm.app.name)
        mock_replace_ingress.assert_called_once_with(
            name=conf_or_rels[1]._ingress_name,
            namespace=self.harness.charm._namespace,
            body=expected_body,
        )

    @patch("charm.NginxIngressCharm._delete_unused_ingresses", autospec=True)
    @patch("charm.NginxIngressCharm._delete_unused_services", autospec=True)
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    def test_ingresses_for_multiple_relations_blocked(
        self,
        mock_api,
        mock_define_service,
        mock_define_ingress,
        mock_report_ips,
        mock_ingress_ips,
        _delete_unused_services,
        _delete_unused_ingresses,
    ):
        """
        arrange: given the harnessed charm
        act: when we create/delete ingresses for multiple relations
        assert: this test will check the Blocked cases for multiple relations
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""
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

        expected_status_message = (
            "Conflicting annotations from relations. Run juju debug-log for details. "
            "Set manually via juju config."
        )
        self.assertEqual("blocked", self.harness.charm.unit.status.name)
        self.assertIn(expected_status_message, self.harness.charm.unit.status.message)

        # Override the rewrite target through the config option. It should fix the problem.
        self.harness.update_config({"retry-errors": "error,timeout"})

        # We still have the issue with the duplicate route.
        expected_status_message = (
            "Duplicate route found; cannot add ingress. Run juju debug-log for details."
        )
        self.assertEqual("blocked", self.harness.charm.unit.status.name)
        self.assertIn(expected_status_message, self.harness.charm.unit.status.message)

        # Update the relation data to have a different route.
        rel_data["path-routes"] = "/funicorn"
        self.harness.update_relation_data(rel_id, "funicorn", rel_data)

        expected_status_message = "Service IP(s): 10.0.1.12"
        self.assertEqual("active", self.harness.charm.unit.status.name)
        self.assertIn(expected_status_message, self.harness.charm.unit.status.message)

    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    def test_ingresses_for_invalid_hostname(
        self,
        mock_api,
        mock_define_service,
        mock_report_ips,
        mock_ingress_ips,
    ):
        """
        arrange: given the harnessed charm
        act: when we create/delete an ingress
        assert: this test will check the Blocked case for invalid hostnames
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""
        mock_list_ingress = mock_api.return_value.list_namespaced_ingress
        # We'll consider we don't have any ingresses set yet.
        mock_list_ingress.return_value.items = []

        # Add the relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "Foo.in.ternal",
            "service-port": "80",
        }
        self._add_ingress_relation("gunicorn", rel_data)

        expected_status_message = INVALID_HOSTNAME_MSG
        self.assertEqual("blocked", self.harness.charm.unit.status.name)
        self.assertIn(expected_status_message, self.harness.charm.unit.status.message)

    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_service")
    @patch("charm.NginxIngressCharm._networking_v1_api")
    def test_ingresses_for_invalid_backend_protocol(
        self,
        mock_api,
        mock_define_service,
        mock_report_ips,
        mock_ingress_ips,
    ):
        """
        arrange: given the harnessed charm
        act: when we create/delete an ingress
        assert: this test will check the Blocked case for invalid backend protocol
        """
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)
        self.harness.charm._authed = True

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""
        mock_list_ingress = mock_api.return_value.list_namespaced_ingress
        # We'll consider we don't have any ingresses set yet.
        mock_list_ingress.return_value.items = []

        # Add the relation.
        rel_data = {
            "service-name": "gunicorn",
            "service-hostname": "foo.in.ternal",
            "service-port": "80",
            "backend-protocol": "foo",
        }
        self._add_ingress_relation("gunicorn", rel_data)

        expected_status_message = INVALID_BACKEND_PROTOCOL_MSG
        self.assertEqual("blocked", self.harness.charm.unit.status.name)
        self.assertIn(expected_status_message, self.harness.charm.unit.status.message)

    @patch("charm.NginxIngressCharm._delete_unused_ingresses", autospec=True)
    @patch("charm.NginxIngressCharm._delete_unused_services", autospec=True)
    @patch("charm.NginxIngressCharm._report_ingress_ips")
    @patch("charm.NginxIngressCharm._report_service_ips")
    @patch("charm.NginxIngressCharm._define_ingress")
    @patch("charm.NginxIngressCharm._define_service")
    def test_missing_relation_data(
        self,
        mock_define_service,
        mock_define_ingress,
        mock_report_ips,
        mock_ingress_ips,
        _delete_unused_services,
        _delete_unused_ingresses,
    ):
        """Test for handling missing relation data."""
        # Setting the leader to True will allow us to test the Ingress creation.
        self.harness.set_leader(True)

        mock_report_ips.return_value = ["10.0.1.12"]
        mock_ingress_ips.return_value = ""

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
        second_body = conf_or_rels[1]._get_k8s_ingress(label=self.harness.charm.app.name)
        expected_body = conf_or_rels[0]._get_k8s_ingress(label=self.harness.charm.app.name)
        expected_body.spec.rules[0].http.paths.extend(second_body.spec.rules[0].http.paths)
        mock_define_ingress.assert_called_once_with(expected_body)


class TestHelpers:
    """Class for testing helper methods."""

    @pytest.mark.parametrize(
        "hostname, expected",
        [
            ("foo-internal", True),
            ("foo.internal1", True),
            ("Foo.internal", False),
            ("foo$internal", False),
        ],
    )
    def test_invalid_hostname_check(self, hostname, expected):
        assert invalid_hostname_check(hostname) == expected

    def test_generate_password(self):
        password = generate_password()
        assert type(password) == str
        assert len(password) == 12


class TestZeroDowntime(unittest.TestCase):
    """Unit test cause for the zero downtime upgrade from ingress relation to nginx-route."""

    def setUp(self) -> None:
        """Test setup."""
        self.harness = Harness(NginxIngressCharm)

    def tearDown(self) -> None:
        """Test cleanup"""
        self.harness.cleanup()

    def _relate_ingress(self, relation_data):
        """Create a new ingress relation with given data.

        Args:
            relation_data: relation data to be set in the new relation.
        """
        relation_id = self.harness.add_relation("ingress", "app")
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="app/0")
        self.harness.update_relation_data(relation_id, "app", relation_data)

    def _relate_nginx_route(self, relation_data):
        """Create a new nginx-route relation with given data.

        Args:
            relation_data: relation data to be set in the new relation.
        """
        relation_id = self.harness.add_relation("nginx-route", "app")
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="app/0")
        self.harness.update_relation_data(relation_id, "app", relation_data)

    def test_dedup_relations(self):
        relation_data = {
            "service-hostname": "foo",
            "service-name": "app",
            "service-model": "test",
            "service-port": "8080",
        }
        self._relate_ingress(relation_data)
        self._relate_nginx_route(relation_data)
        self.harness.begin()
        self.assertEqual(len(self.harness.charm._deduped_relations()), 1)

    def test_no_duplicate_relations(self):
        self._relate_ingress(
            {
                "service-hostname": "foo",
                "service-name": "app",
                "service-model": "test",
                "service-port": "8080",
            }
        )
        self._relate_nginx_route(
            {
                "service-hostname": "foobar",
                "service-name": "app",
                "service-model": "test",
                "service-port": "8080",
            }
        )
        self.harness.begin()
        self.assertEqual(len(self.harness.charm._deduped_relations()), 2)


class TestCertificatesRelation(unittest.TestCase):
    """Unit test cause for the certificates relation."""

    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("charm.NginxIngressCharm._core_v1_api")
    def test_patch_secret(self, mock_core_api):
        mock_secret = MagicMock()
        mock_secret.metadata.name = f"{self.harness.charm.app.name}-cert-tls-secret"
        mock_core_api.return_value.list_namespaced_secret.return_value.items = [mock_secret]
        mock_patch_secret = mock_core_api.return_value.patch_namespaced_secret
        mock_create_secret = mock_core_api.return_value.create_namespaced_secret
        namespace = self.harness.charm._namespace
        metadata = {
            "name": f"{self.harness.charm.app.name}-cert-tls-secret",
            "namespace": namespace,
        }
        data = {"tls.crt": "tls-cert", "tls.key": "tls-key"}
        api_version = "v1"
        kind = "Secret"
        body = kubernetes.client.V1Secret(
            api_version=api_version,
            string_data=data,
            kind=kind,
            metadata=metadata,
            type="kubernetes.io/tls",
        )
        self.harness.charm._create_secret("tls-cert", "tls-key")
        mock_patch_secret.assert_called_once_with(
            f"{self.harness.charm.app.name}-cert-tls-secret", namespace, body
        )
        mock_create_secret.assert_not_called()

    @patch("charm.NginxIngressCharm._core_v1_api")
    def test_create_secret(self, mock_core_api):
        mock_secret = MagicMock()
        mock_secret.metadata.name = "cert-tls-secret-other"
        mock_core_api.return_value.list_namespaced_secret.return_value.items = [mock_secret]
        mock_create_secret = mock_core_api.return_value.create_namespaced_secret
        mock_patch_secret = mock_core_api.return_value.patch_namespaced_secret
        namespace = self.harness.charm._namespace
        metadata = {
            "name": f"{self.harness.charm.app.name}-cert-tls-secret",
            "namespace": namespace,
        }
        data = {"tls.crt": "tls-cert", "tls.key": "tls-key"}
        api_version = "v1"
        kind = "Secret"
        body = kubernetes.client.V1Secret(
            api_version=api_version,
            string_data=data,
            kind=kind,
            metadata=metadata,
            type="kubernetes.io/tls",
        )
        self.harness.charm._create_secret("tls-cert", "tls-key")
        mock_create_secret.assert_called_once_with(namespace, body)
        mock_patch_secret.assert_not_called()

    @patch("charm.NginxIngressCharm._core_v1_api")
    def test_delete_secret(self, mock_core_api):
        mock_secret = MagicMock()
        mock_secret.metadata.name = f"{self.harness.charm.app.name}-cert-tls-secret"
        mock_core_api.return_value.list_namespaced_secret.return_value.items = [mock_secret]
        mock_delete_secret = mock_core_api.return_value.delete_namespaced_secret
        namespace = self.harness.charm._namespace
        self.harness.charm._delete_secret()
        mock_delete_secret.assert_called_once_with(
            f"{self.harness.charm.app.name}-cert-tls-secret", namespace
        )

    @patch("charm.NginxIngressCharm._core_v1_api")
    def test_delete_secret_no_deletion(self, mock_core_api):
        mock_secret = MagicMock()
        mock_secret.metadata.name = "cert-tls-secret-other"
        mock_core_api.return_value.list_namespaced_secret.return_value.items = [mock_secret]
        mock_delete_secret = mock_core_api.return_value.delete_namespaced_secret
        self.harness.charm._delete_secret()
        mock_delete_secret.assert_not_called()

    @patch("charm.generate_password")
    @patch("charm.generate_csr")
    @patch("ops.model.Model.get_secret")
    def test_cert_relation(self, mock_get_secret, mock_gen_csr, mock_gen_pass):
        mock_gen_pass.return_value = "123456789101"
        mock_gen_csr.return_value = b"csr"
        self.harness.add_relation(
            "certificates",
            "self-signed-certificates",
            unit_data={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            },
        )
        mock_gen_pass.assert_called_once()
        mock_gen_csr.assert_called_once()
        assert mock_get_secret.call_count == 2

    @patch("charm.generate_password")
    @patch("charm.generate_csr")
    @patch("ops.model.Model.get_secret")
    def test_create_or_update_cert_key_and_pass_no_relation(
        self, mock_get_secret, mock_gen_csr, mock_gen_pass
    ):
        self.harness.charm._create_or_update_cert_key_and_pass(MagicMock())
        mock_gen_pass.assert_not_called()
        mock_gen_csr.assert_not_called()
        mock_get_secret.assert_not_called()

    @patch("ops.model.Model.get_secret")
    @patch("charm.NginxIngressCharm._delete_secret")
    def test_all_certificates_invalidated(self, mock_delete_secret, mock_get_secret):
        self.harness.charm._on_all_certificates_invalidated(MagicMock())
        mock_get_secret.assert_called_once()
        mock_delete_secret.assert_called_once()

    @patch("charm.NginxIngressCharm._certificate_revoked")
    def test_on_certificate_invalidated_revoke(self, mock_cert_revoked):
        self.harness.add_relation("certificates", "certificates")
        event = CertificateInvalidatedEvent(
            reason="revoked",
            certificate="",
            certificate_signing_request="",
            ca="",
            chain="",
            handle=None,
        )
        self.harness.charm._on_certificate_invalidated(event)
        mock_cert_revoked.assert_called_once()

    @patch("charm.NginxIngressCharm._on_certificate_expiring")
    def test_on_certificate_invalidated_expire(self, mock_cert_expired):
        self.harness.add_relation("certificates", "certificates")
        event = CertificateInvalidatedEvent(
            reason="expired",
            certificate="",
            certificate_signing_request="",
            ca="",
            chain="",
            handle=None,
        )
        self.harness.charm._on_certificate_invalidated(event)
        mock_cert_expired.assert_called_once()

    @patch("charm.NginxIngressCharm._on_certificate_expiring")
    @patch("charm.NginxIngressCharm._certificate_revoked")
    def test_on_certificate_invalidated_blocked(self, mock_cert_revoked, mock_cert_expired):
        event = CertificateInvalidatedEvent(
            reason="expired",
            certificate="",
            certificate_signing_request="",
            ca="",
            chain="",
            handle=None,
        )
        self.harness.charm._on_certificate_invalidated(event)
        mock_cert_expired.assert_not_called()
        mock_cert_revoked.assert_not_called()

    @patch("charm.generate_password")
    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("ops.model.Model.get_secret")
    @patch("charm.NginxIngressCharm._create_or_update_cert_key_and_pass")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    def test_certificate_revoked(
        self,
        mock_cert_renewal,
        mock_cert_create,
        mock_get_secret,
        mock_gen_key,
        mock_gen_csr,
        mock_gen_password,
    ):
        mock_gen_csr.return_value = b"csr"
        mock_gen_key.return_value = b"key"
        mock_gen_password.return_value = "password"
        relation_id = self.harness.add_relation("certificates", "self-signed-certificates")
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            },
        )
        self.harness.charm._certificate_revoked()
        mock_cert_renewal.assert_called_once()
        mock_get_secret.assert_called_once()
        mock_gen_csr.assert_called_once()
        mock_gen_key.assert_called_once()
        mock_gen_password.assert_called_once()

    @patch("charm.generate_password")
    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("ops.model.Model.get_secret")
    @patch("charm.NginxIngressCharm._create_or_update_cert_key_and_pass")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    def test_certificate_revoked_no_relation(
        self,
        mock_cert_renewal,
        mock_cert_create,
        mock_get_secret,
        mock_gen_key,
        mock_gen_csr,
        mock_gen_password,
    ):
        self.harness.charm._certificate_revoked()
        mock_cert_renewal.assert_not_called()
        mock_get_secret.assert_not_called()
        mock_gen_csr.assert_not_called()
        mock_gen_key.assert_not_called()
        mock_gen_password.assert_not_called()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    def test_certificate_expiring(self, mock_cert_renewal):
        self.harness.add_relation(
            "certificates",
            "self-signed-certificates",
            unit_data={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            },
        )
        event = CertificateInvalidatedEvent(
            reason="expired",
            certificate="",
            certificate_signing_request="",
            ca="",
            chain="",
            handle=None,
        )
        self.harness.charm._on_certificate_expiring(event)
        mock_cert_renewal.assert_called_once()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    def test_certificate_expiring_no_relation(self, mock_cert_renewal):
        event = CertificateInvalidatedEvent(
            reason="expired",
            certificate="",
            certificate_signing_request="",
            ca="",
            chain="",
            handle=None,
        )
        self.harness.charm._on_certificate_expiring(event)
        mock_cert_renewal.assert_not_called()

    @patch("charm.NginxIngressCharm._define_ingresses")
    @patch("charm.NginxIngressCharm._create_secret")
    def test_certificate_available_no_relation(self, mock_create_secret, mock_define_ingresses):
        event = CertificateAvailableEvent(
            certificate="", certificate_signing_request="", ca="", chain="", handle=None
        )
        self.harness.charm._on_certificate_available(event)
        mock_create_secret.assert_not_called()
        mock_define_ingresses.assert_not_called()

    @patch("charm.NginxIngressCharm._define_ingresses")
    @patch("charm.NginxIngressCharm._create_secret")
    def test_certificate_available(self, mock_create_secret, mock_define_ingresses):
        self.harness.add_relation(
            "certificates",
            "self-signed-certificates",
            unit_data={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            },
        )
        event = CertificateAvailableEvent(
            certificate="", certificate_signing_request="", ca="", chain=["whatever"], handle=None
        )
        self.harness.charm._on_certificate_available(event)
        mock_create_secret.assert_called_once()
        mock_define_ingresses.assert_called_once()

    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_creation"
    )
    def test_certificate_relation_joined_no_relation(self, mock_create_cert, mock_gen_csr):
        self.harness.charm._on_certificates_relation_joined(MagicMock())
        mock_create_cert.assert_not_called()
        mock_gen_csr.assert_not_called()

    @patch("charm.NginxIngressCharm._networking_v1_api")
    @patch("charm.NginxIngressCharm._certificate_revoked")
    def test_config_changed_cert_relation_no_update(self, mock_cert_revoked, _networking_v1_api):
        """
        arrange: given the harnessed charm
        act: when we change the service name, port and hostname config
        assert: _define_ingress and define_service are only called when changing
        the hostname to a non-empty string, and the status message is appropriate.
        """
        self.harness.set_leader(False)
        mock_ingress = mock.Mock()
        mock_ingress.spec.rules = [
            kubernetes.client.V1IngressRule(
                host="to-be-removed.local",
            )
        ]
        mock_ingresses = _networking_v1_api.return_value.list_namespaced_ingress.return_value
        mock_ingresses.items = [mock_ingress]
        cert_relation_id = self.harness.add_relation("certificates", "certificates")
        ingress_relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(ingress_relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "to-be-removed.local",
            "service-port": "80",
        }
        self.harness.update_relation_data(ingress_relation_id, "gunicorn", relations_data)
        self.harness.update_relation_data(
            relation_id=cert_relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            },
        )
        self.harness.update_config({"service-hostname": "to-be-removed.local"})
        mock_cert_revoked.assert_not_called()

    @patch("charm.NginxIngressCharm._networking_v1_api")
    @patch("charm.NginxIngressCharm._certificate_revoked")
    def test_config_changed_cert_relation_update(self, mock_cert_revoked, _networking_v1_api):
        """
        arrange: given the harnessed charm
        act: when we change the service name, port and hostname config
        assert: _define_ingress and define_service are only called when changing
        the hostname to a non-empty string, and the status message is appropriate.
        """
        self.harness.set_leader(False)
        mock_ingress = mock.Mock()
        mock_ingress.spec.rules = [
            kubernetes.client.V1IngressRule(
                host="to-be-removed.local",
            )
        ]
        mock_ingresses = _networking_v1_api.return_value.list_namespaced_ingress.return_value
        mock_ingresses.items = [mock_ingress]
        cert_relation_id = self.harness.add_relation("certificates", "certificates")
        ingress_relation_id = self.harness.add_relation("ingress", "gunicorn")
        self.harness.add_relation_unit(ingress_relation_id, "gunicorn/0")
        relations_data = {
            "service-name": "gunicorn",
            "service-hostname": "to-be-removed.local",
            "service-port": "80",
        }
        self.harness.update_relation_data(ingress_relation_id, "gunicorn", relations_data)
        self.harness.update_relation_data(
            relation_id=cert_relation_id,
            app_or_unit=self.harness.charm.unit.name,
            key_values={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            },
        )
        self.harness.update_config({"service-hostname": "to-be-removed.local2"})
        mock_cert_revoked.assert_called_once()
