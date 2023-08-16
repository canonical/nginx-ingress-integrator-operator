#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=protected-access,too-few-public-methods,too-many-lines

"""Nginx-ingress-integrator charm file."""

import logging
import time
from typing import Any, List, Optional, cast

import kubernetes.client
from charms.nginx_ingress_integrator.v0.nginx_route import provide_nginx_route
from ops.charm import CharmBase, HookEvent
from ops.main import main
from ops.model import ActiveStatus, Application, BlockedStatus, WaitingStatus

from consts import (
    CREATED_BY_LABEL,
    INVALID_BACKEND_PROTOCOL_MSG,
    INVALID_HOSTNAME_MSG,
    REPORT_INTERVAL_COUNT,
)
from exceptions import InvalidIngressOptionError
from helpers import invalid_hostname_check, is_backend_protocol_valid
from options import _ConfigOrRelation

LOGGER = logging.getLogger(__name__)


def _report_interval_count() -> int:
    """Set interval count for report ingress.

    Returns:
         Interval count
    """
    return REPORT_INTERVAL_COUNT


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
            self.unit.status = WaitingStatus("follower unit is idling")
            return
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

    @property
    def _ingress_option(self) -> Optional[_ConfigOrRelation]:
        nginx_route_relations = self.model.relations["nginx-route"]
        ingress_relations = self.model.relations["ingress"]
        if nginx_route_relations:
            relation = nginx_route_relations[0]
        elif ingress_relations:
            relation = ingress_relations[0]
        else:
            return None
        if relation.data[cast(Application, relation.app)]:
            return _ConfigOrRelation(self.model, self.config, relation=relation)
        return None

    def _validate_ingress_option(self) -> None:
        """Validate ingress option, and raise an exception if there are unresolvable conflicts.

        Raises:
            InvalidIngressOptionError: if the ingress option is invalid.
        """
        if self._ingress_option is None:
            return
        if self._ingress_option.is_ingress_relation:
            if not self._ingress_option.service_hostname:
                raise InvalidIngressOptionError(
                    "service-hostname is not configured for ingress relation"
                )
            if not self._ingress_option.upstream_endpoints:
                raise InvalidIngressOptionError("no endpoints are provided in ingress relation")
        required_fields = "service_hostname", "service_port", "service_name"
        missing_fields = []
        for required_field in required_fields:
            if not getattr(self._ingress_option, required_field):
                missing_fields.append(required_field)
        if missing_fields:
            raise InvalidIngressOptionError(
                f"ingress options missing: [{', '.join(missing_fields)}]"
            )
        if not is_backend_protocol_valid(self._ingress_option.backend_protocol):
            raise InvalidIngressOptionError(INVALID_BACKEND_PROTOCOL_MSG)
        hostnames = [
            self._ingress_option.service_hostname,
            *self._ingress_option.additional_hostnames,
        ]
        if any(not invalid_hostname_check(hostname) for hostname in hostnames):
            raise InvalidIngressOptionError(INVALID_HOSTNAME_MSG)

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
            if self._ingress_option is None
            else self._ingress_option.service_namespace
        )

    def _describe_ingresses_action(self, event: Any) -> None:
        """Handle the 'describe-ingresses' action.

        Args:
            event: Juju event that fires this handler.
        """
        api = self._networking_v1_api()
        ingresses = api.list_namespaced_ingress(namespace=self._namespace)
        event.set_results({"ingresses": ingresses})

    def k8s_auth(self) -> None:
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
        self.k8s_auth()
        return kubernetes.client.CoreV1Api()

    def _networking_v1_api(self) -> kubernetes.client.NetworkingV1Api:
        """Use the v1 beta1 networking API.

        Returns:
            The networking v1 API.
        """
        self.k8s_auth()
        return kubernetes.client.NetworkingV1Api()

    def _discovery_v1_api(self) -> kubernetes.client.DiscoveryV1Api:
        """Use the v1 discovery API.

        Returns:
            The discovery v1 API.
        """
        self.k8s_auth()
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
            if self._ingress_option is not None
            and x.metadata.name == self._ingress_option.k8s_service_name
        ]

    def _report_ingress_ips(self) -> List[str]:
        """Report on ingress IP(s) and return a list of them.

        Returns:
            A list of Ingress IPs.
        """
        api = self._networking_v1_api()
        # Wait up to `interval * count` seconds for ingress IPs.
        count, interval = _report_interval_count(), 1
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

    def _define_endpoint_slice(self) -> None:
        """Create or update an endpoint slice in kubernetes, also remove unused endpoint slices."""
        api = self._discovery_v1_api()
        endpoint_slices = api.list_namespaced_endpoint_slice(
            namespace=self._namespace, label_selector=self._label_selector
        )
        if self._ingress_option is not None and self._ingress_option.use_endpoint_slice:
            body = self._ingress_option.get_k8s_endpoint_slice(self.app.name)
            if self._ingress_option.k8s_endpoint_slice_name in [
                e.metadata.name for e in endpoint_slices.items
            ]:
                api.patch_namespaced_endpoint_slice(
                    name=self._ingress_option.k8s_endpoint_slice_name,
                    namespace=self._namespace,
                    body=body,
                )
                LOGGER.info(
                    "endpoint slice updated in namespace %s with name %s",
                    self._namespace,
                    self._ingress_option.k8s_endpoint_slice_name,
                )
            else:
                api.create_namespaced_endpoint_slice(namespace=self._namespace, body=body)
                LOGGER.info(
                    "endpoint slice created in namespace %s with name %s",
                    self._namespace,
                    self._ingress_option.k8s_endpoint_slice_name,
                )
        for endpoint_slice in endpoint_slices.items:
            if (
                self._ingress_option is not None
                and endpoint_slice.metadata.name == self._ingress_option.k8s_endpoint_slice_name
            ):
                continue
            api.delete_namespaced_endpoint_slice(
                namespace=self._namespace, name=endpoint_slice.metadata.name
            )
            LOGGER.info(
                "endpoint slice deleted in namespace %s with name %s",
                self._namespace,
                endpoint_slice.metadata.name,
            )

    def _define_service(self) -> None:
        """Create or update a service in kubernetes, also remove unused services."""
        api = self._core_v1_api()
        services = api.list_namespaced_service(  # type: ignore[attr-defined]
            namespace=self._namespace, label_selector=self._label_selector
        )
        if self._ingress_option is not None:
            body = self._ingress_option.get_k8s_service(self.app.name)
            if self._ingress_option.k8s_service_name in [x.metadata.name for x in services.items]:
                api.patch_namespaced_service(  # type: ignore[attr-defined]
                    name=self._ingress_option.k8s_service_name,
                    namespace=self._namespace,
                    body=body,
                )
                LOGGER.info(
                    "Service updated in namespace %s with name %s",
                    self._namespace,
                    self._ingress_option.k8s_service_name,
                )
            else:
                api.create_namespaced_service(  # type: ignore[attr-defined]
                    namespace=self._namespace,
                    body=body,
                )
                LOGGER.info(
                    "Service created in namespace %s with name %s",
                    self._namespace,
                    self._ingress_option.k8s_service_name,
                )
        for service in services.items:
            if (
                self._ingress_option is not None
                and service.metadata.name == self._ingress_option.k8s_service_name
            ):
                continue
            api.delete_namespaced_service(
                name=service.metadata.name,
                namespace=self._namespace,
            )
            LOGGER.info(
                "Service deleted in namespace %s with name %s",
                self._namespace,
                service.metadata.name,
            )

    def _look_up_and_set_ingress_class(self, api: Any, body: Any) -> None:
        """Set the configured ingress class, otherwise the cluster's default ingress class.

        Args:
            api: Kubernetes API to perform operations on.
            body: Ingress body.
        """
        ingress_class = self.config["ingress-class"]
        if not ingress_class:
            defaults = [
                item.metadata.name
                for item in api.list_ingress_class().items
                if item.metadata.annotations.get("ingressclass.kubernetes.io/is-default-class")
                == "true"
            ]

            if not defaults:
                LOGGER.warning("Cluster has no default ingress class defined")
                return

            if len(defaults) > 1:
                default_ingress = " ".join(sorted(defaults))
                msg = "Multiple default ingress classes defined, declining to choose between them."
                LOGGER.warning(
                    "%s. They are: %s",
                    msg,
                    default_ingress,
                )
                return

            ingress_class = defaults[0]
            LOGGER.info("Using ingress class %s as it is the cluster's default", ingress_class)

        body.spec.ingress_class_name = ingress_class

    def _define_ingress(self) -> None:
        """Create or update an ingress in kubernetes and remove unused ingresses."""
        api = self._networking_v1_api()
        ingresses = api.list_namespaced_ingress(
            namespace=self._namespace, label_selector=self._label_selector
        )
        if self._ingress_option is not None:
            body = self._ingress_option.get_k8s_ingress(self.app.name)
            self._look_up_and_set_ingress_class(api, body)

            if self._ingress_option.k8s_ingress_name in [x.metadata.name for x in ingresses.items]:
                api.replace_namespaced_ingress(
                    name=self._ingress_option.k8s_ingress_name,
                    namespace=self._namespace,
                    body=body,
                )
                LOGGER.info(
                    "Ingress updated in namespace %s with name %s",
                    self._namespace,
                    self._ingress_option.k8s_ingress_name,
                )
            else:
                api.create_namespaced_ingress(
                    namespace=self._namespace,
                    body=body,
                )
                LOGGER.info(
                    "Ingress created in namespace %s with name %s",
                    self._namespace,
                    self._ingress_option.k8s_ingress_name,
                )
        for ingress in ingresses.items:
            if (
                self._ingress_option is not None
                and ingress.metadata.name == self._ingress_option.k8s_ingress_name
            ):
                continue
            api.delete_namespaced_ingress(namespace=self._namespace, name=ingress.metadata.name)
            LOGGER.info(
                "Ingress removed in namespace %s with name %s",
                self._namespace,
                ingress.metadata.name,
            )

    def _on_config_changed(self, _: HookEvent) -> None:
        """Handle the config changed event.

        Args:
            _: argument not used.

        Raises:
            ApiException: if kubernetes API error happens.
        """
        msg = ""
        # We only want to do anything here if we're the leader to avoid
        # collision if we've scaled out this application.
        if self.unit.is_leader():
            try:
                self._validate_ingress_option()
                self._define_endpoint_slice()
                self._define_service()
                self._define_ingress()
                msgs = []
                if self._ingress_option is not None:
                    self.unit.status = WaitingStatus("Waiting for ingress IP availability")
                    ingress_ips = self._report_ingress_ips()
                    if ingress_ips:
                        msgs.append(f"Ingress IP(s): {', '.join(ingress_ips)}")
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
            except InvalidIngressOptionError as exc:
                self.unit.status = BlockedStatus(exc.msg)
                return
        self.unit.set_workload_version(kubernetes.__version__)
        if self._ingress_option is None:
            self.unit.status = WaitingStatus("waiting for relation")
        else:
            self.unit.status = ActiveStatus(msg)


if __name__ == "__main__":  # pragma: no cover
    main(NginxIngressCharm)
