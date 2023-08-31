#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=protected-access,too-few-public-methods,too-many-lines

"""Nginx-ingress-integrator charm file."""

import logging
import time
from typing import Any, List, Optional

import kubernetes.client
from charms.nginx_ingress_integrator.v0.nginx_route import provide_nginx_route
from charms.traefik_k8s.v2.ingress import IngressPerAppProvider
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from consts import CREATED_BY_LABEL
from controller import (
    EndpointsController,
    EndpointSliceController,
    IngressController,
    ResourceController,
    ResourceType,
    ServiceController,
)
from exceptions import InvalidIngressOptionError
from options import IngressOption, IngressOptionEssence

LOGGER = logging.getLogger(__name__)


class NginxIngressCharm(CharmBase):
    """Charm the service."""

    _authed = False

    def __init__(self, *args) -> None:  # type: ignore[no-untyped-def]
        """Init method for the class.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        if not self.unit.is_leader():
            self.unit.status = WaitingStatus(
                "follower unit is idling, "
                "remove follower units using `juju scale-application {self.app.name} 1`"
            )
            return
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

    def _get_ingress_options(self) -> Optional[IngressOption]:
        """Retrieve the ingress options based on established relations.

        Returns:
            IngressOption instance based on the relation data, or None if no valid relation exists.
        """
        if self.model.relations["nginx-route"]:
            relation = self.model.relations["nginx-route"][0]
            if relation.app is None or not relation.data[relation.app]:
                return None
            option_essence = IngressOptionEssence.from_nginx_route(
                self, self.model.relations["nginx-route"][0]
            )
        elif self.model.relations["ingress"]:
            relation = self.model.relations["ingress"][0]
            if relation.app is None or not relation.data[relation.app]:
                return None
            option_essence = IngressOptionEssence.from_ingress(
                self, self.model.relations["ingress"][0], self._ingress_provider
            )
        else:
            return None
        ingress_option = IngressOption.from_essence(option_essence)
        return ingress_option

    def _k8s_auth(self) -> None:
        """Authenticate to kubernetes."""
        if self._authed:
            return

        kubernetes.config.load_incluster_config()

        self._authed = True

    def _core_v1_api(self) -> kubernetes.client.CoreV1Api:
        """Use the v1 k8s API.

        Returns:
            The core v1 API.
        """
        self._k8s_auth()
        return kubernetes.client.CoreV1Api()

    def _networking_v1_api(self) -> kubernetes.client.NetworkingV1Api:
        """Use the v1 beta1 networking API.

        Returns:
            The networking v1 API.
        """
        self._k8s_auth()
        return kubernetes.client.NetworkingV1Api()

    def _discovery_v1_api(self) -> kubernetes.client.DiscoveryV1Api:
        """Use the v1 discovery API.

        Returns:
            The discovery v1 API.
        """
        self._k8s_auth()
        return kubernetes.client.DiscoveryV1Api()

    def _report_ingress_ips(self, ingress: kubernetes.client.V1Ingress) -> List[str]:
        """Report on ingress IP(s) and return a list of them.

        Args:
            ingress: the target ingress.

        Returns:
            A list of Ingress IPs.
        """
        api = self._networking_v1_api()
        # Wait up to `interval * count` seconds for ingress IPs.
        count, interval = 100, 1
        ips = []
        for _ in range(count):
            ingresses = api.list_namespaced_ingress(  # type: ignore[attr-defined]
                namespace=ingress.metadata.namespace, label_selector=self._label_selector
            )
            try:
                ips = [x.status.load_balancer.ingress[0].ip for x in ingresses.items]
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

    def _define_resources(
        self,
        controller: ResourceController[ResourceType],
        namespace: str,
        options: Optional[IngressOption],
    ) -> Optional[ResourceType]:
        """Create or update a resource in kubernetes.

        Args:
            controller: The controller for the resource type.
            namespace: The namespace for the resource to reside in.
            options: The ingress option

        Returns:
            The name of the created or modified resource, None if no resource is
            modified or created.
        """
        if options is None:
            return None
        resource_list = controller.list_resource(
            namespace=namespace, label_selector=self._label_selector
        )
        body = controller.gen_resource_from_options(options)
        if body.metadata.name in [r.metadata.name for r in resource_list]:
            controller.patch_resource(
                name=body.metadata.name,
                namespace=namespace,
                body=body,
            )
            LOGGER.info(
                f"{controller.name} updated in namespace %s with name %s",
                namespace,
                body.metadata.name,
            )
        else:
            controller.create_resource(namespace=namespace, body=body)
            LOGGER.info(
                f"{controller.name} created in namespace %s with name %s",
                namespace,
                body.metadata.name,
            )
        return body

    def _cleanup_resources(
        self,
        controller: ResourceController[ResourceType],
        namespace: str,
        exclude: Optional[ResourceType],
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
                f"{controller.name} deleted in namespace %s with name %s",
                namespace,
                resource.metadata.name,
            )

    def _define_endpoints(self, options: Optional[IngressOption]) -> None:
        """Create or update an endpoints in kubernetes, also remove unused endpoints.

        Args:
            options: the ingress options used to created resources.
        """
        api = self._core_v1_api()
        controller = EndpointsController(client=api, label=self.app.name)
        namespace = options.service_namespace if options is not None else self.model.name
        updated = None
        if options is not None and options.use_endpoint_slice:
            updated = self._define_resources(controller, namespace=namespace, options=options)
        self._cleanup_resources(controller, namespace=namespace, exclude=updated)

    def _define_endpoint_slice(self, options: Optional[IngressOption]) -> None:
        """Create or update an endpoint slice in kubernetes, also remove unused endpoint slices.

        Args:
            options: the ingress options used to created resources.
        """
        api = self._discovery_v1_api()
        controller = EndpointSliceController(client=api, label=self.app.name)
        namespace = options.service_namespace if options is not None else self.model.name
        updated = None
        if options is not None and options.use_endpoint_slice:
            updated = self._define_resources(controller, namespace=namespace, options=options)
        self._cleanup_resources(controller, namespace=namespace, exclude=updated)

    def _define_service(self, options: Optional[IngressOption]) -> None:
        """Create or update a service in kubernetes, also remove unused services.

        Args:
            options: the ingress options used to created resources.
        """
        api = self._core_v1_api()
        controller = ServiceController(client=api, label=self.app.name)
        namespace = options.service_namespace if options is not None else self.model.name
        self._cleanup_resources(
            controller,
            namespace=namespace,
            exclude=self._define_resources(controller, namespace=namespace, options=options),
        )

    def _define_ingress(
        self, options: Optional[IngressOption]
    ) -> Optional[kubernetes.client.V1Ingress]:
        """Create or update an ingress in kubernetes and remove unused ingresses.

        Args:
            options: the ingress options used to created resources.

        Returns:
            The created or updated ingress.
        """
        api = self._networking_v1_api()
        controller = IngressController(client=api, label=self.app.name)
        namespace = options.service_namespace if options is not None else self.model.name
        updated = self._define_resources(controller, namespace=namespace, options=options)
        self._cleanup_resources(controller, namespace=namespace, exclude=updated)
        return updated

    def _check_precondition(self) -> None:
        """Check the precondition of the charm.

        Raises:
            InvalidIngressOptionError: If both "nginx-route" and "ingress" relations are present
                or some options are invalid.
        """
        nginx_route_relations = self.model.relations["nginx-route"]
        ingress_relations = self.model.relations["ingress"]
        if nginx_route_relations and ingress_relations:
            raise InvalidIngressOptionError(
                "nginx-ingress-integrator cannot establish more than one relation at a time"
            )

    def _update_ingress(self) -> None:
        """Handle the config changed event.

        Raises:
            ApiException: if kubernetes API error happens.
        """
        try:
            self._check_precondition()
            options = self._get_ingress_options()
        except InvalidIngressOptionError as exc:
            self.unit.status = BlockedStatus(exc.msg)
            return
        msg = ""
        try:
            self._define_endpoints(options)
            self._define_endpoint_slice(options)
            self._define_service(options)
            updated_ingress = self._define_ingress(options)
            msgs = []
            if updated_ingress is not None:
                self.unit.status = WaitingStatus("Waiting for ingress IP availability")
                ingress_ips = self._report_ingress_ips(updated_ingress)
                if ingress_ips:
                    msgs.append(f"Ingress IP(s): {', '.join(ingress_ips)}")
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
                return
            raise
        self.unit.set_workload_version(kubernetes.__version__)
        if options is None:
            self.unit.status = WaitingStatus("waiting for relation")
        else:
            self.unit.status = ActiveStatus(msg)

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
