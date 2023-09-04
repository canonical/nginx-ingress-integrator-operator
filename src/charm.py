#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=protected-access,too-few-public-methods,too-many-lines

"""Nginx-ingress-integrator charm file."""

import functools
import logging
import time
from typing import Any, List, Optional, cast

import kubernetes.client
from charms.nginx_ingress_integrator.v0.nginx_route import provide_nginx_route
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Relation, WaitingStatus

from consts import CREATED_BY_LABEL
from controller import (
    AnyResource,
    EndpointsController,
    EndpointSliceController,
    IngressController,
    ResourceController,
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

    def _get_relation(self) -> Optional[Relation]:
        """Get the current effective relation.

        Returns:
            The current effective relation object, None if there are no relation.
        """
        if self.model.get_relation("nginx-route") is not None:
            relation = cast(Relation, self.model.get_relation("nginx-route"))
            if not (relation.app is None or not relation.data[relation.app]):
                return relation
        elif self.model.get_relation("ingress") is not None:
            relation = cast(Relation, self.model.get_relation("ingress"))
            if not (relation.app is None or not relation.data[relation.app]):
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

    def _k8s_auth(self) -> None:
        """Authenticate to kubernetes."""
        if self._authed:
            return

        kubernetes.config.load_incluster_config()

        self._authed = True

    @property
    def _endpoints_controller(self) -> EndpointsController:
        self._k8s_auth()
        api = kubernetes.client.CoreV1Api()
        return EndpointsController(client=api, label=self.app.name)

    @property
    def _endpoint_slice_controller(self) -> EndpointSliceController:
        self._k8s_auth()
        api = kubernetes.client.DiscoveryV1Api()
        return EndpointSliceController(client=api, label=self.app.name)

    @property
    def _service_controller(self) -> ServiceController:
        self._k8s_auth()
        api = kubernetes.client.CoreV1Api()
        return ServiceController(client=api, label=self.app.name)

    @property
    def _ingress_controller(self) -> IngressController:
        self._k8s_auth()
        api = kubernetes.client.NetworkingV1Api()
        return IngressController(client=api, label=self.app.name)

    def _report_ingress_ips(self, ingress: kubernetes.client.V1Ingress) -> List[str]:
        """Report on ingress IP(s) and return a list of them.

        Args:
            ingress: the target ingress.

        Returns:
            A list of Ingress IPs.
        """
        controller = self._ingress_controller
        # Wait up to `interval * count` seconds for ingress IPs.
        count, interval = 100, 1
        ips = []
        for _ in range(count):
            ingresses = controller.list_resource(
                namespace=ingress.metadata.namespace, label_selector=self._label_selector
            )
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

    def _define_resource(
        self,
        controller: ResourceController[AnyResource],
        namespace: str,
        definition: IngressDefinition,
    ) -> AnyResource:
        """Create or update a resource in kubernetes.

        Args:
            controller: The controller for the resource type.
            namespace: The namespace for the resource to reside in.
            definition: The ingress definition

        Returns:
            The name of the created or modified resource, None if no resource is
            modified or created.
        """
        resource_list = controller.list_resource(
            namespace=namespace, label_selector=self._label_selector
        )
        body = controller.gen_resource_from_definition(definition)
        if body.metadata.name in [r.metadata.name for r in resource_list]:
            controller.patch_resource(
                name=body.metadata.name,
                namespace=namespace,
                body=body,
            )
            LOGGER.info(
                "%s updated in namespace %s with name %s",
                controller.name,
                namespace,
                body.metadata.name,
            )
        else:
            controller.create_resource(namespace=namespace, body=body)
            LOGGER.info(
                "%s created in namespace %s with name %s",
                controller.name,
                namespace,
                body.metadata.name,
            )
        return body

    def _cleanup_resources(
        self,
        controller: ResourceController[AnyResource],
        namespace: str,
        exclude: Optional[AnyResource] = None,
    ) -> None:
        """Remove unused resources.

        Args:
            controller: The controller for the resource type.
            namespace: The namespace of resources.
            exclude: The name of resource to be excluded from the cleanup.
        """
        for resource in controller.list_resource(
            namespace=namespace, label_selector=self._label_selector
        ):
            if exclude is not None and resource.metadata.name == exclude.metadata.name:
                continue
            controller.delete_resource(namespace=namespace, name=resource.metadata.name)
            LOGGER.info(
                "%s deleted in namespace %s with name %s",
                controller.name,
                namespace,
                resource.metadata.name,
            )

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
        endpoints_controller = self._endpoints_controller
        endpoint_slice_controller = self._endpoint_slice_controller
        service_controller = self._service_controller
        ingress_controller = self._ingress_controller
        namespace = definition.service_namespace if definition is not None else self.model.name
        endpoints = None
        endpoint_slice = None
        define_resource = functools.partial(
            self._define_resource, namespace=namespace, definition=definition
        )
        cleanup_resources = functools.partial(self._cleanup_resources, namespace=namespace)
        if definition.use_endpoint_slice:
            endpoints = define_resource(controller=endpoints_controller)
            endpoint_slice = define_resource(controller=endpoint_slice_controller)
        service = define_resource(controller=service_controller)
        ingress = define_resource(controller=ingress_controller)
        cleanup_resources(controller=endpoints_controller, exclude=endpoints)
        cleanup_resources(controller=endpoint_slice_controller, exclude=endpoint_slice)
        cleanup_resources(controller=service_controller, exclude=service)
        cleanup_resources(controller=ingress_controller, exclude=ingress)
        return ingress

    def _cleanup(self) -> None:
        """Cleanup all resources managed by the charm."""
        cleanup_resources = functools.partial(self._cleanup_resources, namespace=self.model.name)
        cleanup_resources(controller=self._endpoints_controller)
        cleanup_resources(controller=self._endpoint_slice_controller)
        cleanup_resources(controller=self._service_controller)
        cleanup_resources(controller=self._ingress_controller)

    def _update_ingress(self) -> None:
        """Handle the config changed event.

        Raises:
            ApiException: if kubernetes API error happens.
        """
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
        except kubernetes.client.exceptions.ApiException as exception:
            if exception.status == 403:
                LOGGER.error(
                    "Insufficient permissions to create the k8s service, "
                    "will request `juju trust` to be run"
                )
                juju_trust_cmd = f"juju trust {self.app.name} --scope=cluster"
                self.unit.status = BlockedStatus(
                    f"Insufficient permissions, try: `{juju_trust_cmd}`"
                )
            else:
                raise

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
