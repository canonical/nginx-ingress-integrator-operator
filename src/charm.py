#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=protected-access,too-few-public-methods,too-many-lines

"""Nginx-ingress-integrator charm file."""

import logging
from typing import Any, Dict, List, Optional, Union, cast

import kubernetes.client
from charms.nginx_ingress_integrator.v0.nginx_route import provide_nginx_route
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    Mode,
    TLSCertificatesRequiresV4,
)
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider
from ops.charm import ActionEvent, CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Relation, WaitingStatus

from consts import CREATED_BY_LABEL, TLS_CERT
from controller.endpoint_slice import EndpointSliceController
from controller.endpoints import EndpointsController
from controller.ingress import IngressController
from controller.secret import SecretController
from controller.service import ServiceController
from exceptions import InvalidIngressError
from ingress_definition import IngressDefinition, IngressDefinitionEssence

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

        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.start, self._on_start)

        self.framework.observe(self._ingress_provider.on.data_provided, self._on_data_provided)
        self.framework.observe(self._ingress_provider.on.data_removed, self._on_data_removed)
        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_CERT,
            certificate_requests=self._get_certificate_requests(),
            mode=Mode.APP,
            refresh_events=[
                self.on.config_changed,
                self.on["ingress"].relation_changed,
                self.on["nginx-route"].relation_changed,
            ],
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
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

    def _get_nginx_relation(self) -> Optional[Relation]:
        """Get the current effective relation.

        Returns:
            The current effective relation object, None if there is no relation or it is not ready.
        """
        if self.model.get_relation("nginx-route") is not None:
            relation = cast(Relation, self.model.get_relation("nginx-route"))
            if relation.app is not None and relation.data[relation.app] and relation.units:
                return relation
        elif self.model.get_relation("ingress") is not None:
            relation = cast(Relation, self.model.get_relation("ingress"))
            if relation.app is not None and relation.data[relation.app] and relation.units:
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
                tls_cert=self._get_tls_certs(),
                tls_key=self._get_tls_keys(),
            )
        elif relation.name == "ingress":
            definition_essence = IngressDefinitionEssence(
                model=self.model,
                config=self.config,
                relation=relation,
                ingress_provider=self._ingress_provider,
                tls_cert=self._get_tls_certs(),
                tls_key=self._get_tls_keys(),
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
    def _labels(self) -> Dict[str, str]:
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
        # The charm only supports one relation at a time, so we check if both are present
        # and raise an error if they are.
        if nginx_route_relation is not None and ingress_relation is not None:
            raise InvalidIngressError(
                "Both nginx-route and ingress relations found, please remove either one."
            )
        hostnames = self.get_all_hostnames()
        if ingress_relation is not None and len(hostnames) > 1:
            self._ingress_provider.wipe_ingress_data(ingress_relation)
            raise InvalidIngressError("Ingress relation does not support multiple hostnames.")

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
        secret_list = []
        for hostname in self.get_all_hostnames():
            if self._get_tls_certs().get(hostname):
                secret = secret_controller.define_resource(definition=definition, key=hostname)
                secret_list.append(secret)
                continue
        service = service_controller.define_resource(definition=definition)
        ingress = ingress_controller.define_resource(definition=definition)
        endpoints_controller.cleanup_resources(exclude=endpoints)
        endpoint_slice_controller.cleanup_resources(exclude=endpoint_slice)
        service_controller.cleanup_resources(exclude=service)
        secret_controller.cleanup_resources(exclude=secret_list)
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
            relation = self._get_nginx_relation()
            if relation is None:
                self._cleanup()
                self.unit.status = WaitingStatus("waiting for relation")
                return
            definition = self._get_definition_from_relation(relation)
            self._reconcile(definition)
            self.unit.status = WaitingStatus("Waiting for ingress IP availability")
            namespace = definition.service_namespace if definition is not None else self.model.name
            ingress_controller = self._get_ingress_controller(namespace)
            ingress_ips = ingress_controller.get_ingress_ips()
            message = f"Ingress IP(s): {', '.join(ingress_ips)}" if ingress_ips else ""
            if definition.is_ingress_relation:
                hostnames = self.get_all_hostnames()
                # There will always be an element available in hostnames, as the service hostname
                # is always present. The ingress definition will catch the error if else.
                url = self._generate_ingress_url(hostnames[0], definition.pathroutes)
                self._ingress_provider.publish_url(relation, url)

            self.unit.status = ActiveStatus(message)
        except InvalidIngressError as exc:
            LOGGER.exception("Invalid ingress definition")
            self.unit.status = BlockedStatus(exc.msg)

    def _generate_ingress_url(self, hostname: str, pathroutes: List[str]) -> Optional[str]:
        """Generate the URL for the ingress.

        Args:
            hostname: The hostname to use in the URL.
            pathroutes: The pathroutes to use in the URL.

        Returns:
            The generated URL.

        Raises:
            InvalidIngressError: If there are multiple paths in the pathroutes config.
        """
        # Check if TLS is present in the relation, or by checking secrets.
        # check hostname in certificates
        certs = self._get_tls_certs()
        tls_present = self._get_tls_relation() or certs.get(hostname)
        prefix = "https" if tls_present else "http"

        if len(pathroutes) == 0:
            return f"{prefix}://{hostname}"
        if len(pathroutes) > 1:
            self._ingress_provider.wipe_ingress_data(self._get_nginx_relation())
            raise InvalidIngressError("Ingress relation does not support multiple pathroutes.")
        return f"{prefix}://{hostname}{pathroutes[0]}"

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
        hostname = event.params["hostname"]
        tls_certificates_relation = self._get_tls_relation()
        if not tls_certificates_relation:
            event.fail("Certificates relation not created.")
            return
        provider_certificates, _ = self.certificates.get_assigned_certificates()
        for provider_cert in provider_certificates:
            if provider_cert.certificate.common_name == hostname:
                provider_cert_json = provider_cert.to_json()
                event.set_results(
                    {
                        f"certificate-{hostname}": provider_cert_json["certificate"],
                        f"ca-{hostname}": provider_cert_json["ca"],
                        f"chain-{hostname}": provider_cert_json["chain"],
                    }
                )
                return
        event.fail("Certificate not available")

    def get_all_hostnames(self) -> List[str]:
        """Get a list containing all ingress hostnames.

        Returns:
            A list containing service and additional hostnames
        """
        # The relation will always exist when this method is called
        relation = self._get_nginx_relation()  # type: ignore[arg-type]
        if not relation:
            return []
        try:
            definition = self._get_definition_from_relation(relation)  # type: ignore[arg-type]
        except InvalidIngressError:
            LOGGER.warning("Invalid ingress definition")
            return []
        hostnames = [definition.service_hostname]
        hostnames.extend(definition.additional_hostnames)
        return hostnames

    def _on_certificate_available(self, _: Any) -> None:
        """Handle the TLS Certificate available event."""
        self._update_ingress()

    def _get_tls_relation(self) -> Union[Relation, None]:
        """Get the TLS certificates relation.

        Returns:
            The TLS certificates relation of the charm.
        """
        relation = self.model.get_relation(TLS_CERT)
        return relation

    def _get_certificate_requests(self) -> List[str]:
        """Get the certificate requests for the charm."""
        hostnames = self.get_all_hostnames()
        return [
            CertificateRequestAttributes(common_name=hostname, sans_dns=frozenset([hostname]))
            for hostname in hostnames
        ]

    def _get_tls_certs(self) -> Dict[Union[str, None], Union[str, None]]:
        """Get the TLS certificates provided by the TLS provider."""
        certs: Dict[Union[str, None], Union[str, None]] = {}
        if not hasattr(self, "certificates"):
            return certs
        provider_certs, _ = self.certificates.get_assigned_certificates()
        for provider_cert in provider_certs:
            hostname = provider_cert.certificate.common_name
            certs[hostname] = str(provider_cert.certificate)
        return certs

    def _get_tls_keys(self) -> Dict[Union[str, None], Union[str, None]]:
        """Get the private keys for the charm."""
        keys: Dict[Union[str, None], Union[str, None]] = {}
        if not hasattr(self, "certificates"):
            return keys
        provider_certs, private_key = self.certificates.get_assigned_certificates()
        for provider_cert in provider_certs:
            hostname = provider_cert.certificate.common_name
            keys[hostname] = str(private_key)
        return keys


if __name__ == "__main__":  # pragma: no cover
    main(NginxIngressCharm)
