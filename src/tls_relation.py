# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
# Since the relations invoked in the methods are taken from the charm,
# mypy guesses the relations might be None about all of them.
"""NGINX Ingress TLS relation business logic."""
import secrets
import string
from typing import Dict, List, Union

import kubernetes
from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    generate_csr,
    generate_private_key,
)
from ops.charm import CharmBase
from ops.jujuversion import JujuVersion
from ops.model import Application, Relation, SecretNotFoundError

from consts import TLS_CERT


class TLSRelationService:
    """TLS Relation service class."""

    def __init__(self) -> None:
        """Init method for the class."""
        self.certs: Dict[Union[str, None], Union[str, None]] = {}
        self.keys: Dict[Union[str, None], Union[str, None]] = {}

    def generate_password(self) -> str:
        """Generate a random 12 character password.

        Returns:
            str: Private key string.
        """
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(12))

    def update_cert_on_service_hostname_change(
        self,
        hostnames: List[str],
        tls_certificates_relation: Union[Relation, None],
        namespace: str,
        app_name: Application,
    ) -> List[str]:
        """Handle TLS certificate updates when the charm config changes.

        Args:
            hostnames: Ingress service hostname list.
            tls_certificates_relation: TLS Certificates relation.
            namespace: Kubernetes namespace.
            app_name: Juju app's name.

        Returns:
            bool: If the TLS certificate needs to be updated.
        """
        hostnames_to_revoke: List[str] = []
        if tls_certificates_relation:
            api = kubernetes.client.NetworkingV1Api()
            ingresses = api.list_namespaced_ingress(namespace=namespace)
            hostnames_to_revoke = []
            hostnames_unchanged = []
            for hostname in hostnames:
                csr = tls_certificates_relation.data[app_name].get(f"csr-{hostname}")
                if csr and hostname in [x.spec.rules[0].host for x in ingresses.items]:
                    hostnames_unchanged.append(hostname)
            hostnames_to_revoke = [
                x.spec.rules[0].host
                for x in ingresses.items
                if x.spec.rules[0].host not in hostnames_unchanged
            ]
        return hostnames_to_revoke

    def update_relation_data_fields(
        self, relation_fields: dict, tls_relation: Relation, app: Application
    ) -> None:
        """Update a dict of items from the app relation databag.

        Args:
            relation_fields: items to update
            tls_relation: TLS certificates relation
            app: Charm application
        """
        for key, value in relation_fields.items():
            tls_relation.data[app].update({key: value})

    def pop_relation_data_fields(
        self, relation_fields: list, tls_relation: Relation, app: Application
    ) -> None:
        """Pop a list of items from the app relation databag.

        Args:
            relation_fields: items to pop
            tls_relation: TLS certificates relation
            app: Charm application
        """
        for item in relation_fields:
            tls_relation.data[app].pop(item)

    def get_relation_data_field(
        self, relation_field: str, tls_relation: Relation, app: Application
    ) -> str:
        """Get an item from the app relation databag.

        Args:
            relation_field: item to get
            tls_relation: TLS certificates relation
            app: Charm application

        Returns:
            The value from the field.
        """
        field_value = tls_relation.data[app].get(relation_field)
        return field_value

    def get_hostname_from_csr(self, tls_relation: Relation, app: Application, csr: str) -> str:
        """Get the hostname from a csr.

        Args:
            tls_relation: TLS certificates relation
            app: Charm application
            csr: csr to extract hostname from

        Returns:
            The hostname the csr belongs to.
        """
        csr_dict = {
            key: tls_relation.data[app].get(key)
            for key in tls_relation.data[app]
            if key.startswith("csr-")
        }
        for key in csr_dict:
            if csr_dict[key].replace("\n", "") == csr.replace("\n", ""):
                hostname = key.replace("csr-", "", 1)
                return hostname
        return ""

    def get_tls_relation(self, charm: CharmBase) -> Union[Relation, None]:
        """Get the TLS certificates relation.

        Args:
            charm: The Juju charm containing the relation

        Returns:
            The TLS certificates relation of the charm.
        """
        relation = charm.model.get_relation(TLS_CERT)
        return relation

    # The charm will not have annotations to avoid circular imports.
    def certificate_relation_joined(  # type: ignore[no-untyped-def]
        self, hostname: str, charm
    ) -> None:
        """Handle the TLS Certificate joined event.

        Args:
            hostname: Certificate's hostname.
            charm: The Ingress charm that has the TLS relation
        """
        tls_certificates_relation = self.get_tls_relation(charm)
        peer_relation = charm.model.get_relation("nginx-peers")
        assert isinstance(tls_certificates_relation, Relation)  # nosec
        private_key_dict = {}
        if JujuVersion.from_environ().has_secrets:
            secret = charm.model.get_secret(label=f"private-key-{hostname}")
            secret.grant(tls_certificates_relation)
            private_key_dict["key"] = secret.get_content()["key"].encode()
            private_key_dict["password"] = secret.get_content()["password"].encode()
        else:
            private_key_dict["key"] = self.get_relation_data_field(
                f"key-{hostname}", peer_relation, charm.app
            ).encode()
            private_key_dict["password"] = self.get_relation_data_field(
                f"password-{hostname}", peer_relation, charm.app
            ).encode()
        csr = generate_csr(
            private_key=private_key_dict["key"],
            private_key_password=private_key_dict["password"],
            subject=hostname,
        )
        self.update_relation_data_fields(
            {f"csr-{hostname}": csr.decode()}, tls_certificates_relation, charm.app
        )
        peer_relation = charm.model.get_relation("nginx-peers")
        self.update_relation_data_fields(
            {f"csr-{hostname}": csr.decode()}, peer_relation, charm.app
        )
        charm.certificates.request_certificate_creation(certificate_signing_request=csr)

    def certificate_relation_created(  # type: ignore[no-untyped-def]
        self, hostname: str, charm
    ) -> None:
        """Handle the TLS Certificate created event.

        Args:
            hostname: Certificate's hostname.
            charm: The Ingress charm that has the TLS relation
        """
        tls_certificates_relation = self.get_tls_relation(charm)
        peer_relation = charm.model.get_relation("nginx-peers")
        assert isinstance(tls_certificates_relation, Relation)  # nosec
        private_key_password = self.generate_password().encode()
        private_key = generate_private_key(password=private_key_password)
        private_key_dict = {
            "password": private_key_password.decode(),
            "key": private_key.decode(),
        }
        if JujuVersion.from_environ().has_secrets:
            secret_id = ""  # nosec
            try:
                secret = charm.model.get_secret(label=f"private-key-{hostname}")
                secret.set_content(private_key_dict)
                secret_id = secret.id
            except SecretNotFoundError:
                secret = charm.app.add_secret(
                    content=private_key_dict, label=f"private-key-{hostname}"
                )
                secret_id = secret.id
            self.update_relation_data_fields(
                {f"secret-{hostname}": secret_id}, peer_relation, charm.app
            )
        else:
            peer_relation = charm.model.get_relation("nginx-peers")
            self.update_relation_data_fields(private_key_dict, peer_relation, charm.app)

    def certificate_relation_available(  # type: ignore[no-untyped-def]
        self, charm, event: CertificateAvailableEvent
    ) -> None:
        """Handle the TLS Certificate available event.

        Args:
            charm: The Ingress charm that has the TLS relation
            event: The event that fires this method.
        """
        tls_certificates_relation = self.get_tls_relation(charm)
        assert isinstance(tls_certificates_relation, Relation)  # nosec
        hostname = self.get_hostname_from_csr(
            tls_certificates_relation, charm.app, event.certificate_signing_request
        )
        self.update_relation_data_fields(
            {
                f"certificate-{hostname}": event.certificate,
                f"ca-{hostname}": event.ca,
                f"chain-{hostname}": str(event.chain[0]),
            },
            tls_certificates_relation,
            charm.app,
        )
        peer_relation = charm.model.get_relation("nginx-peers")
        self.update_relation_data_fields(
            {
                f"certificate-{hostname}": event.certificate,
                f"ca-{hostname}": event.ca,
                f"chain-{hostname}": str(event.chain[0]),
            },
            peer_relation,
            charm.app,
        )
        private_key = ""
        if JujuVersion.from_environ().has_secrets:
            secret = charm.model.get_secret(label=f"private-key-{hostname}")
            private_key = secret.get_content()["key"]
        else:
            private_key = self.get_relation_data_field(f"key-{hostname}", peer_relation, charm.app)
        self.certs[hostname] = event.certificate
        self.keys[hostname] = private_key

    def certificate_expiring(  # type: ignore[no-untyped-def]
        self,
        charm,
        event: Union[CertificateExpiringEvent, CertificateInvalidatedEvent],
    ) -> None:
        """Handle the TLS Certificate expiring event.

        Args:
            charm: The Ingress charm that has the TLS relation
            event: The event that fires this method.
        """
        tls_certificates_relation = self.get_tls_relation(charm)
        peer_relation = charm.model.get_relation("nginx-peers")
        assert isinstance(tls_certificates_relation, Relation)  # nosec
        hostname = self.get_hostname_from_csr(
            tls_certificates_relation, charm.app, event.certificate_signing_request
        )
        old_csr = self.get_relation_data_field(
            f"csr-{hostname}", tls_certificates_relation, charm.app
        )
        private_key_dict = {}
        if JujuVersion.from_environ().has_secrets:
            secret = charm.model.get_secret(label=f"private-key-{hostname}")
            secret.grant(tls_certificates_relation)
            private_key_dict["key"] = secret.get_content()["key"].encode()
            private_key_dict["password"] = secret.get_content()["password"].encode()
        else:
            private_key_dict["key"] = self.get_relation_data_field(
                f"key-{hostname}", peer_relation, charm.app
            ).encode()
            private_key_dict["password"] = self.get_relation_data_field(
                f"password-{hostname}", peer_relation, charm.app
            ).encode()
        new_csr = generate_csr(
            private_key=private_key_dict["key"],
            private_key_password=private_key_dict["password"],
            subject=hostname,
        )
        charm.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr.encode(),
            new_certificate_signing_request=new_csr,
        )
        self.update_relation_data_fields(
            {f"csr-{hostname}": new_csr.decode()}, tls_certificates_relation, charm.app
        )
        peer_relation = charm.model.get_relation("nginx-peers")
        self.update_relation_data_fields(
            {f"csr-{hostname}": new_csr.decode()}, peer_relation, charm.app
        )
