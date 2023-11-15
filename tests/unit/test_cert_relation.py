# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import typing
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
from ops.charm import ActionEvent
from ops.testing import Harness

from charm import NginxIngressCharm
from tests.unit.constants import TEST_NAMESPACE
from tls_relation import TLSRelationService


class TestCertificatesRelation(unittest.TestCase):
    """Unit test cause for the certificates relation."""

    @pytest.mark.usefixtures("patch_load_incluster_config")
    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(NginxIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def set_up_all_relations(self):
        """Set up certificates and nginx-route relations.

        Returns:
            A tuple containing both relation IDs.
        """
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
            unit_data={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            },
        )
        return nginx_route_rel_id, tls_rel_id

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

    def set_up_cert_relation(self):
        """Set up certificates relation."""
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

    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_generate_password(self):
        tls_rel = TLSRelationService()
        password = tls_rel.generate_password()
        assert type(password) == str
        assert len(password) == 12

    @patch("tls_relation.TLSRelationService.generate_password")
    @patch("charm.generate_csr")
    @patch("charm.NginxIngressCharm._update_ingress")
    @patch("ops.model.Model.get_secret")
    @patch("ops.JujuVersion.has_secrets")
    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_cert_relation(
        self, mock_has_secrets, mock_get_secret, mock_update_ingress, mock_gen_csr, mock_gen_pass
    ):
        mock_gen_pass.return_value = "123456789101"
        mock_gen_csr.return_value = b"csr"
        mock_has_secrets.return_value = True
        self.harness.set_leader(True)
        self.set_up_all_relations()
        mock_gen_pass.assert_called_once()
        mock_gen_csr.assert_called_once()
        assert mock_get_secret.call_count == 2

    @patch("tls_relation.TLSRelationService.generate_password")
    @patch("charm.generate_csr")
    @patch("charm.NginxIngressCharm._update_ingress")
    @patch("ops.model.Model.get_secret")
    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_cert_relation_no_secrets(
        self, mock_get_secret, mock_update_ingress, mock_gen_csr, mock_gen_pass
    ):
        mock_gen_pass.return_value = "123456789101"
        mock_gen_csr.return_value = b"csr"
        self.harness.set_leader(True)
        self.set_up_all_relations()
        mock_gen_pass.assert_called_once()
        mock_gen_csr.assert_called_once()
        mock_get_secret.assert_not_called()

    @patch("tls_relation.TLSRelationService.generate_password")
    @patch("charm.generate_csr")
    @patch("ops.model.Model.get_secret")
    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_on_certificates_relation_created_no_relation(
        self, mock_get_secret, mock_gen_csr, mock_gen_pass
    ):
        self.harness.charm._on_certificates_relation_created(MagicMock())
        mock_gen_pass.assert_not_called()
        mock_gen_csr.assert_not_called()
        mock_get_secret.assert_not_called()

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_all_certificates_invalidated_no_secret(self, mock_ingress_update):
        self.harness.set_leader(True)
        self.set_up_nginx_relation()
        relation_id = self.harness.add_relation("certificates", "self-signed-certificates")
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "private_key": "whatever",
                "private_key_password": "whatever",
            },
        )
        self.harness.charm._on_all_certificates_invalidated(MagicMock())

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("ops.model.Model.get_secret")
    @patch("charm.NginxIngressCharm._update_ingress")
    @patch("ops.JujuVersion.has_secrets")
    def test_all_certificates_invalidated(
        self, mock_has_secrets, mock_ingress_update, mock_get_secret
    ):
        mock_has_secrets.return_value = True
        self.harness.set_leader(True)
        self.set_up_nginx_relation()
        self.harness.charm._on_all_certificates_invalidated(MagicMock())
        mock_get_secret.assert_called_once()

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._certificate_revoked")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_on_certificate_invalidated_revoke(self, mock_update_ingress, mock_cert_revoked):
        self.harness.set_leader(True)
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

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._on_certificate_expiring")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_on_certificate_invalidated_expire(self, mock_update_ingress, mock_cert_expired):
        self.harness.set_leader(True)
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

    @pytest.mark.usefixtures("patch_load_incluster_config")
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

    @patch("tls_relation.TLSRelationService.generate_password")
    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("ops.model.Model.get_secret")
    @patch("charm.NginxIngressCharm._on_certificates_relation_created")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    @patch("charm.NginxIngressCharm._update_ingress")
    @patch("ops.JujuVersion.has_secrets")
    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_certificate_revoked(
        self,
        mock_has_secrets,
        mock_update_ingress,
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
        mock_has_secrets.return_value = True
        self.harness.set_leader(True)
        self.set_up_nginx_relation()
        relation_id = self.harness.add_relation("certificates", "self-signed-certificates")
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
                "private_key": "whatever",
                "private_key_password": "whatever",
            },
        )
        self.harness.charm._certificate_revoked()
        mock_cert_renewal.assert_called_once()
        mock_get_secret.assert_called_once()
        mock_gen_csr.assert_called_once()
        mock_gen_key.assert_called_once()
        mock_gen_password.assert_called_once()

    @patch("tls_relation.TLSRelationService.generate_password")
    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("ops.model.Model.get_secret")
    @patch("charm.NginxIngressCharm._on_certificates_relation_created")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    @patch("charm.NginxIngressCharm._update_ingress")
    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_certificate_revoked_no_secrets(
        self,
        mock_update_ingress,
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
        self.harness.set_leader(True)
        self.set_up_nginx_relation()
        relation_id = self.harness.add_relation("certificates", "self-signed-certificates")
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
                "key": "whatever",
                "password": "whatever",
            },
        )
        self.harness.charm._certificate_revoked()
        mock_cert_renewal.assert_called_once()
        mock_get_secret.assert_not_called()
        mock_gen_csr.assert_called_once()
        mock_gen_key.assert_called_once()
        mock_gen_password.assert_called_once()

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("tls_relation.TLSRelationService.generate_password")
    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("ops.model.Model.get_secret")
    @patch("charm.NginxIngressCharm._on_certificates_relation_created")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    @patch("charm.NginxIngressCharm._cleanup")
    def test_certificate_revoked_no_cert_relation(
        self,
        mock_cleanup,
        mock_cert_renewal,
        mock_cert_create,
        mock_get_secret,
        mock_gen_key,
        mock_gen_csr,
        mock_gen_password,
    ):
        relation_id = self.harness.add_relation("certificates", "self-signed-certificates")
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
                "private_key": "whatever",
                "private_key_password": "whatever",
            },
        )
        self.harness.charm._certificate_revoked()
        mock_cert_renewal.assert_not_called()
        mock_get_secret.assert_not_called()
        mock_gen_csr.assert_not_called()
        mock_gen_key.assert_not_called()
        mock_gen_password.assert_not_called()
        mock_cleanup.asset_called_once()

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("tls_relation.TLSRelationService.generate_password")
    @patch("charm.generate_csr")
    @patch("charm.generate_private_key")
    @patch("ops.model.Model.get_secret")
    @patch("charm.NginxIngressCharm._on_certificates_relation_created")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    def test_certificate_revoked_no_nginx_relation(
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

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_renewal"
    )
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_certificate_expiring(self, mock_ingress_update, mock_cert_renewal):
        self.harness.set_leader(True)
        self.set_up_all_relations()
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

    @pytest.mark.usefixtures("patch_load_incluster_config")
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

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_certificate_available_no_relation(self, mock_update):
        event = CertificateAvailableEvent(
            certificate="", certificate_signing_request="", ca="", chain="", handle=None
        )
        self.harness.charm._on_certificate_available(event)
        mock_update.assert_not_called()

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_certificate_available(self, mock_update):
        self.harness.set_leader(True)
        self.set_up_all_relations()
        event = CertificateAvailableEvent(
            certificate="", certificate_signing_request="", ca="", chain=["whatever"], handle=None
        )
        self.harness.charm._on_certificate_available(event)
        assert mock_update.call_count == 3

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_creation"
    )
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_certificate_relation_joined(
        self, mock_ingress_update, mock_create_cert, mock_gen_csr
    ):
        mock_gen_csr.return_value = b"csr"
        event = CertificateAvailableEvent(
            certificate="", certificate_signing_request="", ca="", chain="", handle=None
        )
        self.harness.set_leader(True)
        self.set_up_all_relations()
        self.harness.charm._on_certificates_relation_joined(event)
        assert mock_create_cert.call_count == 2
        assert mock_gen_csr.call_count == 2

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._cleanup")
    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_creation"
    )
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_certificate_relation_joined_no_nginx_relation(
        self, mock_ingress_update, mock_create_cert, mock_gen_csr, mock_cleanup
    ):
        self.harness.set_leader(True)
        self.set_up_cert_relation()
        self.harness.charm._on_certificates_relation_joined(MagicMock())
        mock_create_cert.assert_not_called()
        mock_gen_csr.assert_not_called()
        assert mock_cleanup.call_count == 2

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._cleanup")
    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates"
        ".TLSCertificatesRequiresV2.request_certificate_creation"
    )
    def test_certificate_relation_joined_no_cert_relation(
        self, mock_create_cert, mock_gen_csr, mock_cleanup
    ):
        self.set_up_nginx_relation()
        self.harness.charm._on_certificates_relation_joined(MagicMock())
        mock_create_cert.assert_not_called()
        mock_gen_csr.assert_not_called()
        mock_cleanup.assert_not_called()

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._certificate_revoked")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_config_changed_cert_relation_no_update(self, mock_update_ingress, mock_cert_revoked):
        """
        arrange: given the harnessed charm
        act: when we change the service name, port and hostname config
        assert: _define_ingress and define_service are only called when changing
        the hostname to a non-empty string, and the status message is appropriate.
        """
        with mock.patch.object(kubernetes.client, "NetworkingV1Api") as mock_networking_v1_api:
            self.harness.set_leader(True)
            mock_ingress = mock.Mock()
            mock_ingress.spec.rules = [
                kubernetes.client.V1IngressRule(
                    host="to-be-removed.local",
                )
            ]
            mock_ingresses = (
                mock_networking_v1_api.return_value.list_namespaced_ingress.return_value
            )
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

    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_update_cert_on_service_hostname_change(self):
        """
        arrange: given the harnessed charm
        act: when we change the service name, port and hostname config
        assert: _define_ingress and define_service are only called when changing
        the hostname to a non-empty string, and the status message is appropriate.
        """
        with mock.patch.object(kubernetes.client, "NetworkingV1Api") as mock_networking_v1_api:
            tls_rel = TLSRelationService()
            service_hostname = "hostname"
            mock_ingress = mock.Mock()
            mock_ingress.spec.rules = [
                kubernetes.client.V1IngressRule(
                    host="to-be-removed.local",
                )
            ]
            mock_ingresses = (
                mock_networking_v1_api.return_value.list_namespaced_ingress.return_value
            )
            mock_ingresses.items = [mock_ingress]
            tls_certificates_relation = MagicMock()
            unit_name = self.harness.charm.unit
            tls_certificates_relation.return_value.data[unit_name].return_value = {"csr": "csr"}
            result = tls_rel.update_cert_on_service_hostname_change(
                service_hostname, tls_certificates_relation, TEST_NAMESPACE, unit_name
            )
            assert result

    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_config_changed_cert_relation_update(self):
        """
        arrange: given the harnessed charm
        act: when we change the service name, port and hostname config
        assert: _define_ingress and define_service are only called when changing
        the hostname to a non-empty string, and the status message is appropriate.
        """
        with mock.patch.object(kubernetes.client, "NetworkingV1Api") as mock_networking_v1_api:
            tls_rel = TLSRelationService()
            service_hostname = "to-be-removed.local"
            mock_ingress = mock.Mock()
            mock_ingress.spec.rules = [
                kubernetes.client.V1IngressRule(
                    host="to-be-removed.local",
                )
            ]
            mock_ingresses = (
                mock_networking_v1_api.return_value.list_namespaced_ingress.return_value
            )
            mock_ingresses.items = [mock_ingress]
            tls_certificates_relation = MagicMock()
            unit_name = self.harness.charm.unit
            tls_certificates_relation.return_value.data[unit_name].return_value = {"csr": "csr"}
            result = tls_rel.update_cert_on_service_hostname_change(
                service_hostname, tls_certificates_relation, TEST_NAMESPACE, unit_name
            )
            assert not result

    @pytest.mark.usefixtures("patch_load_incluster_config")
    @patch("charm.NginxIngressCharm._update_ingress")
    def test_get_certificate_action(self, mock_update_ingress):
        """
        arrange: an email and a password
        act: when the _on_add_admin_action method is executed
        assert: the indico command to add the user is executed with the appropriate parameters.
        """
        self.harness.set_leader(True)
        _, tls_rel_id = self.set_up_all_relations()
        self.harness.update_relation_data(
            relation_id=tls_rel_id,
            app_or_unit=self.harness.charm.app.name,
            key_values={
                "csr": "whatever",
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            },
        )
        self.harness.disable_hooks()

        charm: NginxIngressCharm = typing.cast(NginxIngressCharm, self.harness.charm)

        event = MagicMock(spec=ActionEvent)
        charm._on_get_certificate_action(event)
        event.set_results.assert_called_with(
            {
                "certificate": "whatever",
                "ca": "whatever",
                "chain": "whatever",
            }
        )

    @pytest.mark.usefixtures("patch_load_incluster_config")
    def test_get_certificate_action_no_relation(self):
        """
        arrange: an email and a password
        act: when the _on_add_admin_action method is executed
        assert: the indico command to add the user is executed with the appropriate parameters.
        """
        self.harness.disable_hooks()

        charm: NginxIngressCharm = typing.cast(NginxIngressCharm, self.harness.charm)

        event = MagicMock(spec=ActionEvent)
        charm._on_get_certificate_action(event)
        event.set_results.assert_not_called()
