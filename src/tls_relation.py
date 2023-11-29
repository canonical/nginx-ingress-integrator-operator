# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""NGINX Ingress TLS relation business logic."""
import secrets
import string
from typing import Dict, List, Union

import kubernetes
from ops.model import Application, Relation


class TLSRelationService:
    """TLS Relation service class."""

    def __init__(self) -> None:
        """Init method for the class."""
        self.cert: Dict[Union[str, None], Union[str, None]] = {}
        self.key: Dict[Union[str, None], Union[str, None]] = {}

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
    ) -> list:
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

    def get_hostname_from_csr(
        self, tls_relation: Relation, app: Application, csr: str
    ) -> Union[str, None]:
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
        return None
