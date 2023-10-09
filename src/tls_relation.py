# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""NGINX Ingress TLS relation business logic."""
import secrets
import string
from typing import Union

import kubernetes
from ops.model import Relation, Unit


class TLSRelationService:
    """TLS Relation service class."""

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

    def create_secret(self, tls_cert: str, tls_key: str, namespace: str) -> None:
        """Create a kubernetes secret for TLS.

        Args:
            tls_cert: TLS certificate
            tls_key: TLS private_key
            namespace: kubernetes namespace.
        """
        api = kubernetes.client.CoreV1Api()
        data = {"tls.crt": tls_cert, "tls.key": tls_key}
        api_version = "v1"
        kind = "Secret"
        body = kubernetes.client.V1Secret(
            api_version=api_version,
            string_data=data,
            kind=kind,
            metadata={"name": "cert-tls-secret", "namespace": namespace},
            type="kubernetes.io/tls",
        )
        secret_list = api.list_namespaced_secret(
            namespace=namespace, label_selector=None
        )  # type: ignore[attr-defined]
        if "cert-tls-secret" in [x.metadata.name for x in secret_list.items]:
            api.patch_namespaced_secret("cert-tls-secret", namespace, body)
            return
        api.create_namespaced_secret(namespace, body)

    def delete_secret(self, namespace: str) -> None:
        """Delete kubernetes secret for TLS.

        Args:
            namespace: kubernetes namespace.
        """
        api = kubernetes.client.CoreV1Api()
        secret_list = api.list_namespaced_secret(  # type: ignore[attr-defined]
            namespace=namespace, label_selector=None
        )
        if "cert-tls-secret" in [x.metadata.name for x in secret_list.items]:
            api.delete_namespaced_secret("cert-tls-secret", namespace)
            return
