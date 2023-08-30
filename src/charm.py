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
from ops.charm import CharmBase, HookEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from consts import CREATED_BY_LABEL
from controller import (
    EndpointsController,
    EndpointSliceController,
    IngressController,
    ResourceController,
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

        self._ingress_options: Optional[IngressOption] = None

        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.describe_ingresses_action, self._describe_ingresses_action)
        self.framework.observe(self.on.start, self._on_config_changed)

        self.framework.observe(self.on["ingress"].relation_changed, self._on_config_changed)
        self.framework.observe(self.on["ingress"].relation_broken, self._on_config_changed)

        provide_nginx_route(
            charm=self,
            on_nginx_route_available=self._on_config_changed,
            on_nginx_route_broken=self._on_config_changed,
        )

    def _get_ingress_options(self) -> Optional[IngressOption]:
        """Retrieve the ingress options based on established relations.

        Returns:
            IngressOption instance based on the relation data, or None if no valid relation exists.

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
        if nginx_route_relations:
            relation = nginx_route_relations[0]
        elif ingress_relations:
            relation = ingress_relations[0]
        else:
            return None
        if relation.app is not None and relation.data[relation.app]:
            ingress_option_essence = IngressOptionEssence(
                self.model, self.config, relation=relation
            )
            ingress_option = IngressOption.from_essence(ingress_option_essence)
            return ingress_option
        return None

    @property
    def _namespace(self) -> Any:
        """Namespace for this ingress.

        Returns:
            The namespace for this Ingress.
        """
        # We're querying the first one here because this will always be the same
        # for all instances. It would be very unusual for a relation to specify
        # this (arguably we should remove this as a relation option), so if set
        # via config it will be the same for all relations.
        return (
            self.model.name
            if self._ingress_options is None
            else self._ingress_options.service_namespace
        )

    def _describe_ingresses_action(self, event: Any) -> None:
        """Handle the 'describe-ingresses' action.

        Args:
            event: Juju event that fires this handler.
        """
        try:
            self._ingress_options = self._get_ingress_options()
        except InvalidIngressOptionError:
            pass
        api = self._networking_v1_api()
        ingresses = api.list_namespaced_ingress(
            namespace=self._namespace, label_selector=self._label_selector
        )
        event.set_results({"ingresses": ingresses})

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

    def _report_service_ips(self) -> List[str]:
        """Report on service IP(s) and return a list of them.

        Returns:
            A list of service IPs.
        """
        api = self._core_v1_api()
        services = api.list_namespaced_service(  # type: ignore[attr-defined]
            namespace=self._namespace, label_selector=self._label_selector
        )
        return [
            x.spec.cluster_ip
            for x in services.items
            if self._ingress_options is not None
            and x.metadata.name == self._ingress_options.k8s_service_name
        ]

    def _report_ingress_ips(self) -> List[str]:
        """Report on ingress IP(s) and return a list of them.

        Returns:
            A list of Ingress IPs.
        """
        api = self._networking_v1_api()
        # Wait up to `interval * count` seconds for ingress IPs.
        count, interval = 100, 1
        ips = []
        for _ in range(count):
            ingresses = api.list_namespaced_ingress(  # type: ignore[attr-defined]
                namespace=self._namespace, label_selector=self._label_selector
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

    def _define_resources(self, controller: ResourceController) -> Optional[str]:
        """Create or update a resource in kubernetes.

        Args:
            controller: The controller for the resource type.

        Returns:
            The name of the created or modified resource, None if no resource is
            modified or created.
        """
        if self._ingress_options is None:
            return None
        resource_list = controller.list_resource(
            namespace=self._namespace, label_selector=self._label_selector
        )
        body = controller.gen_resource_from_options(self._ingress_options)
        if body.metadata.name in [r.metadata.name for r in resource_list]:
            controller.patch_resource(
                name=body.metadata.name,
                namespace=self._namespace,
                body=body,
            )
            LOGGER.info(
                f"{controller.name} updated in namespace %s with name %s",
                self._namespace,
                body.metadata.name,
            )
        else:
            controller.create_resource(namespace=self._namespace, body=body)
            LOGGER.info(
                f"{controller.name} created in namespace %s with name %s",
                self._namespace,
                body.metadata.name,
            )
        return body.metadata.name

    def _cleanup_resources(self, controller: ResourceController, exclude: Optional[str]) -> None:
        """Remove unused resources.

        Args:
            controller: The controller for the resource type.
            exclude: The name of resource to be excluded from the clean up.
        """
        for resource in controller.list_resource(
            namespace=self._namespace, label_selector=self._label_selector
        ):
            if exclude is not None and resource.metadata.name == exclude:
                continue
            controller.delete_resource(namespace=self._namespace, name=resource.metadata.name)
            LOGGER.info(
                f"{controller.name} deleted in namespace %s with name %s",
                self._namespace,
                resource.metadata.name,
            )

    def _define_endpoints(self) -> None:
        """Create or update an endpoints in kubernetes, also remove unused endpoints."""
        api = self._core_v1_api()
        controller = EndpointsController(client=api, label=self.app.name)
        exclude = None
        if self._ingress_options is not None and self._ingress_options.use_endpoint_slice:
            exclude = self._define_resources(controller)
        self._cleanup_resources(controller, exclude=exclude)

    def _define_endpoint_slice(self) -> None:
        """Create or update an endpoint slice in kubernetes, also remove unused endpoint slices."""
        api = self._discovery_v1_api()
        controller = EndpointSliceController(client=api, label=self.app.name)
        exclude = None
        if self._ingress_options is not None and self._ingress_options.use_endpoint_slice:
            exclude = self._define_resources(controller)
        self._cleanup_resources(controller, exclude=exclude)

    def _define_service(self) -> None:
        """Create or update a service in kubernetes, also remove unused services."""
        api = self._core_v1_api()
        controller = ServiceController(client=api, label=self.app.name)
        self._cleanup_resources(controller, exclude=self._define_resources(controller))

    def _define_ingress(self) -> None:
        """Create or update an ingress in kubernetes and remove unused ingresses."""
        api = self._networking_v1_api()
        controller = IngressController(client=api, label=self.app.name)
        self._define_resources(controller)
        self._cleanup_resources(controller, exclude=self._define_resources(controller))

    def _on_config_changed(self, _: HookEvent) -> None:
        """Handle the config changed event.

        Args:
            _: argument not used.

        Raises:
            ApiException: if kubernetes API error happens.
        """
        try:
            self._ingress_options = self._get_ingress_options()
        except InvalidIngressOptionError as exc:
            self.unit.status = BlockedStatus(exc.msg)
            return
        msg = ""
        try:
            self._define_endpoints()
            self._define_endpoint_slice()
            self._define_service()
            self._define_ingress()
            msgs = []
            if self._ingress_options is not None:
                self.unit.status = WaitingStatus("Waiting for ingress IP availability")
                ingress_ips = self._report_ingress_ips()
                if ingress_ips:
                    msgs.append(f"Ingress IP(s): {', '.join(ingress_ips)}")
                if not self._ingress_options.is_ingress_relation:
                    msgs.append(f"Service IP(s): {', '.join(self._report_service_ips())}")
                    msg = ", ".join(msgs)
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
        if self._ingress_options is None:
            self.unit.status = WaitingStatus("waiting for relation")
        else:
            self.unit.status = ActiveStatus(msg)


if __name__ == "__main__":  # pragma: no cover
    main(NginxIngressCharm)
