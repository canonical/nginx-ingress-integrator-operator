# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
# mypy: disable-error-code="arg-type"

import unittest
from typing import Tuple
from unittest.mock import MagicMock, patch

import pytest
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateAvailableEvent,
    PrivateKey,
    ProviderCertificate,
)
from ops.testing import Harness

from charm import NginxIngressCharm


class TestCertificatesRelation(unittest.TestCase):
    """Test cases for the certificates relation."""

    @pytest.mark.usefixtures("patch_load_incluster_config")
    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

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

    def generate_certificates(self) -> Tuple[ProviderCertificate, PrivateKey]:
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
