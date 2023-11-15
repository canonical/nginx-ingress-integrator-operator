#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=protected-access,too-few-public-methods,too-many-lines

"""Nginx-ingress-integrator charm file."""

import logging
import typing
from typing import Any, Optional, Union, cast

import kubernetes.client
from charms.nginx_ingress_integrator.v0.nginx_route import provide_nginx_route
from charms.tls_certificates_interface.v2.tls_certificates import (
    AllCertificatesInvalidatedEvent,
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider
from ops.charm import ActionEvent, CharmBase, RelationCreatedEvent, RelationJoinedEvent
from ops.jujuversion import JujuVersion
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
    ModelError,
    Relation,
    WaitingStatus,
)

from consts import CREATED_BY_LABEL
from controller import (
    EndpointsController,
    EndpointSliceController,
    IngressController,
    SecretController,
    ServiceController,
)
from exceptions import InvalidIngressError
from ingress_definition import IngressDefinition, IngressDefinitionEssence
from tls_relation import TLSRelationService

LOGGER = logging.getLogger(__name__)


class NginxIngressCharm(CharmBase):
    """The main charm class for the nginx-ingress-integrator charm."""

    _authed = False

    def __init__(self, *args) -> None:  # type: ignore[no-untyped-def]
        """Init method for the class.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        kubernetes.config.load_incluster_config()

        self._ingress_provider = IngressPerAppProvider(charm=self)
        self._tls = TLSRelationService()

        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.start, self._on_start)

        self.framework.observe(self._ingress_provider.on.data_provided, self._on_data_provided)
        self.framework.observe(self._ingress_provider.on.data_removed, self._on_data_removed)
        self.certificates = TLSCertificatesRequiresV2(self, "certificates")
        self.framework.observe(
            self.on.certificates_relation_created, self._on_certificates_relation_created
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.certificates.on.certificate_invalidated, self._on_certificate_invalidated
        )
        self.framework.observe(
            self.certificates.on.all_certificates_invalidated,
            self._on_all_certificates_invalidated,
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)

        provide_nginx_route(
            charm=self,
            on_nginx_route_available=self._on_nginx_route_available,
            on_nginx_route_broken=self._on_nginx_route_broken,
        )

    def _get_endpoints_controller(self, namespace: str) -> EndpointsController:
        """Create an endpoints controller.

        Args:
            namespace: Kubernetes namespace.

        Returns:
            An EndpointsController instance.
        """
        return EndpointsController(namespace=namespace, labels=self._labels)

    def _get_endpoint_slice_controller(self, namespace: str) -> EndpointSliceController:
        """Create an endpoint slice controller.

        Args:
            namespace: Kubernetes namespace.

        Returns:
            An EndpointSliceController instance.
        """
        return EndpointSliceController(namespace=namespace, labels=self._labels)

    def _get_service_controller(self, namespace: str) -> ServiceController:
        """Create a service controller.

        Args:
            namespace: Kubernetes namespace.

        Returns:
            A ServiceController instance.
        """
        return ServiceController(namespace=namespace, labels=self._labels)

    def _get_secret_controller(self, namespace: str) -> SecretController:
        """Create a service controller.

        Args:
            namespace: Kubernetes namespace.

        Returns:
            A ServiceController instance.
        """
        return SecretController(namespace=namespace, labels=self._labels)

    def _get_ingress_controller(self, namespace: str) -> IngressController:
        """Create an ingress controller.

        Args:
            namespace: Kubernetes namespace.

        Returns:
            An IngressController instance.
        """
        return IngressController(namespace=namespace, labels=self._labels)

    def _get_relation(self) -> Optional[Relation]:
        """Get the current effective relation.

        Returns:
            The current effective relation object, None if there are no relation.
        """
        if self.model.get_relation("nginx-route") is not None:
            relation = cast(Relation, self.model.get_relation("nginx-route"))
            if relation.app is not None and relation.data[relation.app]:
                return relation
        elif self.model.get_relation("ingress") is not None:
            relation = cast(Relation, self.model.get_relation("ingress"))
            if relation.app is not None and relation.data[relation.app]:
                return relation
        return None

    def _get_definition_from_relation(self, relation: Relation) -> IngressDefinition:
        """Get the IngressDefinition from the given relation.

        Args:
            relation: The source relation object.

        Return:
            The IngressDefinition corresponding to the provided relation.

        Raises:
            ValueError: unknown relation name.
        """
        if relation.name == "nginx-route":
            definition_essence = IngressDefinitionEssence(
                model=self.model,
                config=self.config,
                relation=relation,
                tls_cert=self._tls.cert,
                tls_key=self._tls.key,
            )
        elif relation.name == "ingress":
            definition_essence = IngressDefinitionEssence(
                model=self.model,
                config=self.config,
                relation=relation,
                ingress_provider=self._ingress_provider,
                tls_cert=self._tls.cert,
                tls_key=self._tls.key,
            )
        else:
            raise ValueError(f"Invalid relation: {relation.name}")
        ingress_definition = IngressDefinition.from_essence(definition_essence)
        return ingress_definition

    @property
    def _label_selector(self) -> str:
        """Get the label selector to select resources created by this app."""
        return f"{CREATED_BY_LABEL}={self.app.name}"

    @property
    def _labels(self) -> typing.Dict[str, str]:
        """Get labels assigned to resources created by this app."""
        return {CREATED_BY_LABEL: self.app.name}

    def _check_precondition(self) -> None:
        """Check the precondition of the charm.

        Raises:
            InvalidIngressError: If both "nginx-route" and "ingress" relations are present
                or some definition are invalid.
        """
        if not self.unit.is_leader():
            raise InvalidIngressError(
                "this charm only supports a single unit, "
                "please remove the additional units "
                f"using `juju scale-application {self.app.name} 1`"
            )
        nginx_route_relation = self.model.get_relation("nginx-route")
        ingress_relation = self.model.get_relation("ingress")
        if nginx_route_relation is not None and ingress_relation is not None:
            raise InvalidIngressError(
                "nginx-ingress-integrator cannot establish more than one relation at a time"
            )

    def _reconcile(self, definition: IngressDefinition) -> None:
        """Reconcile ingress related resources based on the provided definition.

        Args:
            definition: Configuration definition for the ingress. If not provided, no resources
                will be created but the cleanup will still run.
        """
        namespace = definition.service_namespace if definition is not None else self.model.name
        endpoints_controller = self._get_endpoints_controller(namespace=namespace)
        endpoint_slice_controller = self._get_endpoint_slice_controller(namespace=namespace)
        service_controller = self._get_service_controller(namespace=namespace)
        secret_controller = self._get_secret_controller(namespace=namespace)
        ingress_controller = self._get_ingress_controller(namespace=namespace)
        endpoints = None
        endpoint_slice = None
        if definition.use_endpoint_slice:
            endpoints = endpoints_controller.define_resource(definition=definition)
            endpoint_slice = endpoint_slice_controller.define_resource(definition=definition)
        secret = secret_controller.define_resource(definition=definition)
        service = service_controller.define_resource(definition=definition)
        ingress = ingress_controller.define_resource(definition=definition)
        endpoints_controller.cleanup_resources(exclude=endpoints)
        endpoint_slice_controller.cleanup_resources(exclude=endpoint_slice)
        service_controller.cleanup_resources(exclude=service)
        secret_controller.cleanup_resources(exclude=secret)
        ingress_controller.cleanup_resources(exclude=ingress)

    def _cleanup(self) -> None:
        """Cleanup all resources managed by the charm."""
        self._get_endpoints_controller(namespace=self.model.name).cleanup_resources()
        self._get_endpoint_slice_controller(namespace=self.model.name).cleanup_resources()
        self._get_service_controller(namespace=self.model.name).cleanup_resources()
        self._get_secret_controller(namespace=self.model.name).cleanup_resources()
        self._get_ingress_controller(namespace=self.model.name).cleanup_resources()

    def _update_ingress(self) -> None:
        """Handle the config changed event."""
        self.unit.set_workload_version(kubernetes.__version__)
        try:
            self._check_precondition()
            relation = self._get_relation()
            if relation is None:
                self._cleanup()
                self.unit.status = WaitingStatus("waiting for relation")
                return
            definition = self._get_definition_from_relation(relation)
            tls_certificates_relation = self.model.get_relation("certificates")
            unit_name = self.unit
            if self._tls.update_cert_on_service_hostname_change(
                definition.service_hostname,
                tls_certificates_relation,
                definition.service_namespace,
                unit_name,
            ):
                self._certificate_revoked()
            self._reconcile(definition)
            self.unit.status = WaitingStatus("Waiting for ingress IP availability")
            namespace = definition.service_namespace if definition is not None else self.model.name
            ingress_controller = self._get_ingress_controller(namespace)
            ingress_ips = ingress_controller.get_ingress_ips()
            message = f"Ingress IP(s): {', '.join(ingress_ips)}" if ingress_ips else ""
            self.unit.status = ActiveStatus(message)
        except InvalidIngressError as exc:
            self.unit.status = BlockedStatus(exc.msg)

    def _on_config_changed(self, _: Any) -> None:
        """Handle the config-changed event."""
        self._update_ingress()

    def _on_start(self, _: Any) -> None:
        """Handle the start event."""
        self._update_ingress()

    def _on_data_provided(self, _: Any) -> None:
        """Handle the data-provided event."""
        self._update_ingress()

    def _on_data_removed(self, _: Any) -> None:
        """Handle the data-removed event."""
        self._update_ingress()

    def _on_nginx_route_available(self, _: Any) -> None:
        """Handle the nginx-route-available event."""
        self._update_ingress()

    def _on_nginx_route_broken(self, _: Any) -> None:
        """Handle the nginx-route-broken event."""
        self._update_ingress()

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        """Triggered when users run the `get-certificate` Juju action.

        Args:
            event: Juju event
        """
        tls_certificates_relation = self.model.get_relation("certificates")
        if not tls_certificates_relation:
            event.fail("Certificates relation not created.")
            return
        tls_rel_data = tls_certificates_relation.data[self.app]
        if tls_rel_data["certificate"]:
            event.set_results(
                {
                    "certificate": tls_rel_data["certificate"],
                    "ca": tls_rel_data["ca"],
                    "chain": tls_rel_data["chain"],
                }
            )
        else:
            event.fail("Certificate not available")

    def _on_certificates_relation_created(self, event: RelationCreatedEvent) -> None:
        """Handle the TLS Certificate relation created event.

        Args:
            event: The event that fires this method.
        """
        tls_certificates_relation = self.model.get_relation("certificates")
        if not tls_certificates_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        private_key_password = self._tls.generate_password().encode()
        private_key = generate_private_key(password=private_key_password)
        private_key_dict = {"password": private_key_password.decode(), "key": private_key.decode()}
        tls_rel_data = tls_certificates_relation.data[self.app]
        if JujuVersion.from_environ().has_secrets:
            try:
                secret = self.model.get_secret(label="private-key")
                secret.set_content(private_key_dict)
            except ModelError:
                secret = self.app.add_secret(content=private_key_dict, label="private-key")
        tls_rel_data.update(private_key_dict)

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Handle the TLS Certificate relation joined event.

        Args:
            event: The event that fires this method.
        """
        tls_certificates_relation = self.model.get_relation("certificates")
        if not tls_certificates_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        relation = self._get_relation()
        if relation is None:
            self._cleanup()
            self.unit.status = WaitingStatus("waiting for relation")
            return
        tls_rel_data = tls_certificates_relation.data[self.app]
        private_key_dict = {}
        if JujuVersion.from_environ().has_secrets:
            secret = self.model.get_secret(label="private-key")
            secret.grant(tls_certificates_relation)
            private_key_dict["key"] = secret.get_content()["key"].encode()
            private_key_dict["password"] = secret.get_content()["password"].encode()
        else:
            private_key_dict["key"] = tls_rel_data.get("key").encode()
            private_key_dict["password"] = tls_rel_data.get("password").encode()
        definition = self._get_definition_from_relation(relation)
        subject = definition.service_hostname if definition is not None else self.model.name
        csr = generate_csr(
            private_key=private_key_dict["key"],
            private_key_password=private_key_dict["password"],
            subject=subject,
        )
        tls_rel_data.update({"csr": csr.decode()})
        self.certificates.request_certificate_creation(certificate_signing_request=csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handle the TLS Certificate available event.

        Args:
            event: The event that fires this method.
        """
        tls_certificates_relation = self.model.get_relation("certificates")
        if not tls_certificates_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        tls_rel_data = tls_certificates_relation.data[self.app]
        tls_rel_data.update({"certificate": event.certificate})
        tls_rel_data.update({"ca": event.ca})
        tls_rel_data.update({"chain": str(event.chain[0])})
        private_key = ""
        if JujuVersion.from_environ().has_secrets:
            secret = self.model.get_secret(label="private-key")
            private_key = secret.get_content()["key"]
        else:
            private_key = tls_rel_data.get("key")
        self._tls.cert = event.certificate
        self._tls.key = private_key
        self._update_ingress()
        self.unit.status = ActiveStatus()

    def _on_certificate_expiring(
        self, event: Union[CertificateExpiringEvent, CertificateInvalidatedEvent]
    ) -> None:
        """Handle the TLS Certificate expiring event.

        Args:
            event: The event that fires this method.
        """
        tls_certificates_relation = self.model.get_relation("certificates")
        if not tls_certificates_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        relation = self._get_relation()
        if relation is None:
            self._cleanup()
            self.unit.status = WaitingStatus("waiting for relation")
            return
        tls_rel_data = tls_certificates_relation.data[self.app]
        old_csr = tls_rel_data.get("csr")
        private_key_dict = {}
        if JujuVersion.from_environ().has_secrets:
            secret = self.model.get_secret(label="private-key")
            secret.grant(tls_certificates_relation)
            private_key_dict["key"] = secret.get_content()["key"].encode()
            private_key_dict["password"] = secret.get_content()["password"].encode()
        else:
            private_key_dict["key"] = tls_rel_data.get("key").encode()
            private_key_dict["password"] = tls_rel_data.get("password").encode()
        definition = self._get_definition_from_relation(relation)
        subject = definition.service_hostname if definition is not None else self.model.name
        new_csr = generate_csr(
            private_key=private_key_dict["key"],
            private_key_password=private_key_dict["password"],
            subject=subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr.encode(),
            new_certificate_signing_request=new_csr,
        )
        tls_rel_data = tls_certificates_relation.data[self.app]
        tls_rel_data.update({"csr": new_csr.decode()})

    def _certificate_revoked(self) -> None:
        """Handle TLS Certificate revocation."""
        tls_certificates_relation = self.model.get_relation("certificates")
        if not tls_certificates_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            return
        relation = self._get_relation()
        if relation is None:
            self._cleanup()
            self.unit.status = WaitingStatus("waiting for relation")
            return
        tls_rel_data = tls_certificates_relation.data[self.app]
        old_csr = tls_rel_data.get("csr")
        if JujuVersion.from_environ().has_secrets:
            secret = self.model.get_secret(label="private-key")
            secret.remove_all_revisions()
        else:
            tls_rel_data.pop("private_key")
            tls_rel_data.pop("private_key_password")
        private_key_password = self._tls.generate_password().encode()
        private_key = generate_private_key(password=private_key_password)
        private_key_dict = {"password": private_key_password.decode(), "key": private_key.decode()}
        tls_rel_data.update(private_key_dict)
        new_secret = self.app.add_secret(content=private_key_dict, label="private-key")
        new_secret.grant(tls_certificates_relation)
        new_secret_data = new_secret.get_content()
        definition = self._get_definition_from_relation(relation)
        subject = definition.service_hostname if definition is not None else self.model.name
        new_csr = generate_csr(
            private_key=new_secret_data["key"].encode(),
            private_key_password=new_secret_data["password"].encode(),
            subject=subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr.encode(),
            new_certificate_signing_request=new_csr,
        )
        tls_rel_data = tls_certificates_relation.data[self.app]
        tls_rel_data.update({"csr": new_csr.decode()})
        tls_rel_data.pop("certificate")
        tls_rel_data.pop("ca")
        tls_rel_data.pop("chain")

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        """Handle the TLS Certificate invalidation event.

        Args:
            event: The event that fires this method.
        """
        tls_certificates_relation = self.model.get_relation("certificates")
        if not tls_certificates_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        if event.reason == "revoked":
            self._certificate_revoked()
        if event.reason == "expired":
            self._on_certificate_expiring(event)
        self.unit.status = MaintenanceStatus("Waiting for new certificate")

    def _on_all_certificates_invalidated(self, _: AllCertificatesInvalidatedEvent) -> None:
        """Handle the TLS Certificate relation broken event.

        Args:
            _: The event that fires this method.
        """
        if JujuVersion.from_environ().has_secrets:
            secret = self.model.get_secret(label="private-key")
            secret.remove_all_revisions()


if __name__ == "__main__":  # pragma: no cover
    main(NginxIngressCharm)
