#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=protected-access,too-few-public-methods,too-many-lines

"""Nginx-ingress-integrator charm file."""

import logging
import time
import typing
from typing import Any, List, Optional, cast

import kubernetes.client
from charms.nginx_ingress_integrator.v0.nginx_route import provide_nginx_route
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Relation, WaitingStatus

from consts import CREATED_BY_LABEL
from controller import (
    EndpointsController,
    EndpointSliceController,
    IngressController,
    ServiceController,
)
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
        """
        if relation.name == "nginx-route":
            definition_essence = IngressDefinitionEssence(
                model=self.model, config=self.config, relation=relation
            )
        else:
            definition_essence = IngressDefinitionEssence(
                model=self.model,
                config=self.config,
                relation=relation,
                ingress_provider=self._ingress_provider,
            )
        ingress_definition = IngressDefinition.from_essence(definition_essence)
        return ingress_definition

    def _report_ingress_ips(self, ingress: kubernetes.client.V1Ingress) -> List[str]:
        """Report on ingress IP(s) and return a list of them.

        Args:
            ingress: the target ingress.

        Returns:
            A list of Ingress IPs.
        """
        controller = self._get_ingress_controller(namespace=ingress.metadata.namespace)
        # Wait up to `interval * count` seconds for ingress IPs.
        count, interval = 100, 1
        ips = []
        for _ in range(count):
            ingresses = controller.list_resource()
            try:
                ips = [x.status.load_balancer.ingress[0].ip for x in ingresses]
            except TypeError:
                # We have no IPs yet.
                pass
            if ips:
                break
            LOGGER.info("Sleeping for %s seconds to wait for ingress IP", interval)
            time.sleep(interval)
        return ips

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

    def _reconcile(self, definition: IngressDefinition) -> kubernetes.client.V1Ingress:
        """Reconcile ingress related resources based on the provided definition.

        Args:
            definition: Configuration definition for the ingress. If not provided, no resources
                will be created but the cleanup will still run.

        Returns:
            The created or modified ingress resource, None if no ingress resource was created or
                modified.
        """
        namespace = definition.service_namespace if definition is not None else self.model.name
        endpoints_controller = self._get_endpoints_controller(namespace=namespace)
        endpoint_slice_controller = self._get_endpoint_slice_controller(namespace=namespace)
        service_controller = self._get_service_controller(namespace=namespace)
        ingress_controller = self._get_ingress_controller(namespace=namespace)
        endpoints = None
        endpoint_slice = None
        if definition.use_endpoint_slice:
            endpoints = endpoints_controller.define_resource(definition=definition)
            endpoint_slice = endpoint_slice_controller.define_resource(definition=definition)
        service = service_controller.define_resource(definition=definition)
        ingress = ingress_controller.define_resource(definition=definition)
        endpoints_controller.cleanup_resources(exclude=endpoints)
        endpoint_slice_controller.cleanup_resources(exclude=endpoint_slice)
        service_controller.cleanup_resources(exclude=service)
        ingress_controller.cleanup_resources(exclude=ingress)
        return ingress

    def _cleanup(self) -> None:
        """Cleanup all resources managed by the charm."""
        endpoints_controller = self._get_endpoints_controller(namespace=self.model.name)
        endpoint_slice_controller = self._get_endpoint_slice_controller(namespace=self.model.name)
        service_controller = self._get_service_controller(namespace=self.model.name)
        ingress_controller = self._get_ingress_controller(namespace=self.model.name)
        endpoints_controller.cleanup_resources()
        endpoint_slice_controller.cleanup_resources()
        service_controller.cleanup_resources()
        ingress_controller.cleanup_resources()

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
            ingress = self._reconcile(definition)
            self.unit.status = WaitingStatus("Waiting for ingress IP availability")
            ingress_ips = self._report_ingress_ips(ingress)
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


if __name__ == "__main__":  # pragma: no cover
    main(NginxIngressCharm)
