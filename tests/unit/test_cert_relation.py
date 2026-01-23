# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
# mypy: disable-error-code="arg-type"

import json
import typing
import unittest
from unittest.mock import MagicMock, patch

import pytest
from charmlibs.interfaces.tls_certificates import (
    Certificate,
    CertificateAvailableEvent,
    PrivateKey,
    ProviderCertificate,
)
from ops.charm import ActionEvent
from ops.testing import Harness

from charm import NginxIngressCharm


class TestCertificatesRelation(unittest.TestCase):
    """Test cases for the certificates relation."""

    @pytest.mark.usefixtures("patch_load_incluster_config")
    def setUp(self):
        """Setup the harness object."""
        self._patch = patch.object(NginxIngressCharm, "_has_secrets", MagicMock(return_value=True))
        self._patch.start()
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def tearDown(self):
        """Tear down test fixtures."""
        self._patch.stop()

    def set_up_all_relations(self):
        """Set up certificates and nginx-route relations.

        Returns:
            A tuple containing both relation IDs.
        """
        peer_rel_id = self.harness.add_relation(
            "nginx-peers",
            "nginx-ingress-integrator",
            app_data={
                "csr-example.com": "whatever",
                "certificate-example.com": "whatever",
                "ca-example.com": "whatever",
                "chain-example.com": "whatever",
                "key-example.com": "whatever",
                "password-example.com": "whatever",
            },
        )
        nginx_route_rel_id = self.harness.add_relation(
            "nginx-route",
            "gunicorn",
            app_data={
                "service-hostname": "example.com",
                "service-port": "8080",
                "service-namespace": "test",
                "service-name": "app",
            },
            unit_data={"host": '"test.svc.cluster.local"', "ip": '"10.0.0.1"'},
        )
        tls_rel_id = self.harness.add_relation(
            "certificates",
            "self-signed-certificates",
        )
        return nginx_route_rel_id, tls_rel_id, peer_rel_id

    def set_up_nginx_relation(self):
        """Set up nginx-route relation."""
        self.harness.add_relation(
            "nginx-route",
            "gunicorn",
            app_data={
                "service-hostname": "example.com",
                "service-port": "8080",
                "service-namespace": "test",
                "service-name": "app",
            },
            unit_data={"host": '"test.svc.cluster.local"', "ip": '"10.0.0.1"'},
        )

    def generate_certificates(self) -> typing.Tuple[ProviderCertificate, PrivateKey]:
        """Generate certificates for testing.

        Returns:
            Tuple[ProviderCertificate, PrivateKey]: Tuple of provider certificate and private key.
        """
        with open("tests/unit/cert.pem", encoding="utf-8") as f:
            cert = f.read()
        with open("tests/unit/key.pem", encoding="utf-8") as f:
            key = f.read()

        provider_cert_mock = MagicMock()
        private_key = PrivateKey.from_string(key)
        certificate = Certificate.from_string(cert)
        provider_cert_mock.certificate = certificate
        provider_cert_mock.ca = certificate
        provider_cert_mock.chain = [certificate]
        provider_cert_mock.to_json.return_value = json.dumps(
            {
                "certificate": cert,
                "ca": cert,
                "chain": [cert],
                "key": key,
            }
        )
        return provider_cert_mock, private_key

    @patch("controller.resource.ResourceController.cleanup_resources")
    @patch("controller.endpoints.EndpointsController.cleanup_resources")
    @patch("controller.service.ServiceController.define_resource")
    @patch("controller.secret.SecretController.cleanup_resources")
    @patch("controller.secret.SecretController.define_resource")
    @patch("controller.ingress.IngressController.define_resource")
    @patch("controller.ingress.IngressController.get_ingress_ips")
    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_given_when_certificate_available_then_ingress_updated(
        self,
        mock_get_ingress_ips,
        mock_define_ingress_resource,
        mock_define_secret_resource,
        mock_cleanup_secret_resources,
        mock_define_service_resource,
        mock_cleanup_endpoints_resources,
        mock_cleanup_resource_resources,
    ):
        self.harness.set_leader(True)
        self.set_up_nginx_relation()
        provider_cert_mock, private_key = self.generate_certificates()

        self.harness.charm.certificates = MagicMock()
        self.harness.charm.certificates.get_assigned_certificates.return_value = (
            [provider_cert_mock],
            private_key,
        )
        event = CertificateAvailableEvent(
            certificate="", certificate_signing_request="", ca="", chain="", handle=None
        )

        self.harness.charm._on_certificate_available(event)

        mock_define_secret_resource.assert_called()

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_get_certificate_action(self, mock_update_ingress):
        """
        arrange: a hostname
        act: when the _on_get_certificate_action method is executed
        assert: the charm gets the certificate appropriately.
        """
        provider_cert_mock, private_key = self.generate_certificates()
        self.harness.charm.certificates = MagicMock()
        self.harness.charm.certificates.get_assigned_certificates.return_value = (
            [provider_cert_mock],
            private_key,
        )
        self.harness.set_leader(True)
        _, _tls_rel_id, _ = self.set_up_all_relations()
        self.harness.disable_hooks()
        charm: NginxIngressCharm = typing.cast(NginxIngressCharm, self.harness.charm)
        event = MagicMock(spec=ActionEvent)
        event.params = {
            "hostname": "example.com",
        }

        charm._on_get_certificate_action(event)

        event.set_results.assert_called_with(
            {
                "certificate-example.com": json.loads(provider_cert_mock.to_json())["certificate"],
                "ca-example.com": json.loads(provider_cert_mock.to_json())["ca"],
                "chain-example.com": json.loads(provider_cert_mock.to_json())["chain"],
            }
        )

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_get_certificate_action_no_tls_relation(self, mock_update_ingress):
        """
        arrange: a hostname
        act: when the _on_get_certificate_action method is executed
        assert: the charm gets the certificate appropriately.
        """
        provider_cert_mock, private_key = self.generate_certificates()
        self.harness.charm.certificates = MagicMock()
        self.harness.charm.certificates.get_assigned_certificates.return_value = (
            [provider_cert_mock],
            private_key,
        )
        self.harness.set_leader(True)
        self.harness.disable_hooks()
        charm: NginxIngressCharm = typing.cast(NginxIngressCharm, self.harness.charm)
        event = MagicMock(spec=ActionEvent)
        event.params = {
            "hostname": "example.com",
        }

        charm._on_get_certificate_action(event)

        event.fail.assert_called_with("Certificates relation not created.")

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_get_certificate_action_cert_not_available(self, mock_update_ingress):
        """
        arrange: a hostname
        act: when the _on_get_certificate_action method is executed
        assert: the charm gets the certificate appropriately.
        """
        _provider_cert_mock, private_key = self.generate_certificates()
        self.harness.charm.certificates = MagicMock()
        self.harness.charm.certificates.get_assigned_certificates.return_value = (
            [],
            private_key,
        )
        self.harness.set_leader(True)
        _, _tls_rel_id, _ = self.set_up_all_relations()
        self.harness.disable_hooks()
        charm: NginxIngressCharm = typing.cast(NginxIngressCharm, self.harness.charm)
        event = MagicMock(spec=ActionEvent)
        event.params = {
            "hostname": "example.com",
        }

        charm._on_get_certificate_action(event)

        event.fail.assert_called_with("Certificate not available")
