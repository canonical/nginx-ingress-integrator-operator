# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""NGINX Ingress TLS relation business logic."""
import secrets
import string
from typing import Union

import kubernetes
from ops.model import Application, Relation, Unit


class TLSRelationService:
    """TLS Relation service class."""

    def __init__(self) -> None:
        """Init method for the class."""
        self.cert: Union[str, None] = None
        self.key: Union[str, None] = None

    def generate_password(self) -> str:
        """Generate a random 12 character password.

        Returns:
            str: Private key string.
        """
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(12))

    def update_cert_on_service_hostname_change(
        self,
        service_hostname: str,
        tls_certificates_relation: Union[Relation, None],
        namespace: str,
        unit_name: Unit,
    ) -> bool:
        """Handle TLS certificate updates when the charm config changes.

        Args:
            service_hostname: Ingress service hostname.
            tls_certificates_relation: TLS Certificates relation.
            namespace: Kubernetes namespace.
            unit_name: Juju unit's name.

        Returns:
            bool: If the TLS certificate needs to be updated.
        """
        if tls_certificates_relation:
            api = kubernetes.client.NetworkingV1Api()
            ingresses = api.list_namespaced_ingress(namespace=namespace)
            csr = tls_certificates_relation.data[unit_name].get("csr")
            if csr and service_hostname not in [x.spec.rules[0].host for x in ingresses.items]:
                return True
        return False

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
            relation_field: items to pop
            tls_relation: TLS certificates relation
            app: Charm application

        Returns:
            The value from the field.
        """
        field_value = tls_relation.data[app].get(relation_field)
        return field_value
