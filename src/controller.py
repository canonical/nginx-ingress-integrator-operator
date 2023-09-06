# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""nginx-ingress-integrator k8s resource controllers."""

import abc
import functools
import logging
import typing

import kubernetes.client

from exceptions import InvalidIngressError
from ingress_definition import IngressDefinition

logger = logging.getLogger(__name__)

AnyResource = typing.TypeVar(  # pylint: disable=invalid-name
    "AnyResource",
    kubernetes.client.V1Endpoints,
    kubernetes.client.V1EndpointSlice,
    kubernetes.client.V1Service,
    kubernetes.client.V1Ingress,
)


def _map_k8s_auth_exception(func: typing.Callable) -> typing.Callable:
    """Remap the kubernetes 403 ApiException to InvalidIngressError.

    Args:
        func: function to be wrapped.

    Returns:
        A wrapped function.
    """

    @functools.wraps(func)
    def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        """Remap the kubernetes 403 ApiException to InvalidIngressError."""
        try:
            return func(*args, **kwargs)
        except kubernetes.client.exceptions.ApiException as exc:
            if exc.status == 403:
                logger.error(
                    "Insufficient permissions to create the k8s service, "
                    "will request `juju trust` to be run"
                )
                juju_trust_cmd = "juju trust <nginx-ingress-integrator> --scope=cluster"
                raise InvalidIngressError(
                    f"Insufficient permissions, try: `{juju_trust_cmd}`"
                ) from exc
            raise

    return wrapper


class ResourceController(typing.Protocol[AnyResource]):
    """Abstract base class for a generic Kubernetes resource controller."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Abstract property that returns the name of the resource type.

        Returns:
            Name of the resource type.
        """

    @abc.abstractmethod
    def gen_resource_from_definition(self, definition: IngressDefinition) -> AnyResource:
        """Abstract method to generate a resource from ingress definition.

        Args:
            definition: Ingress definition to use for generating the resource.

        Returns:
            Generated resource.
        """

    @abc.abstractmethod
    def create_resource(self, namespace: str, body: AnyResource) -> None:
        """Abstract method to create a new resource in a given namespace.

        Args:
            namespace: The namespace in which to create the resource.
            body: The resource object to create.
        """

    @abc.abstractmethod
    def patch_resource(self, namespace: str, name: str, body: AnyResource) -> None:
        """Abstract method to patch an existing resource in a given namespace.

        Args:
            namespace: The namespace in which the resource resides.
            name: The name of the resource to patch.
            body: The modified resource object.
        """

    @abc.abstractmethod
    def list_resource(self, namespace: str, label_selector: str) -> typing.List[AnyResource]:
        """Abstract method to list resources in a given namespace based on a label selector.

        Args:
            namespace: The namespace to list resources from.
            label_selector: The label selector to filter resources.

        Returns:
            A list of matched resources.
        """

    @abc.abstractmethod
    def delete_resource(self, namespace: str, name: str) -> None:
        """Abstract method to delete a resource from a given namespace.

        Args:
            namespace: The namespace from which to delete the resource.
            name: The name of the resource to delete.
        """


class EndpointsController(ResourceController[kubernetes.client.V1Endpoints]):
    """Kubernetes Endpoints resource controller."""

    def __init__(self, labels: typing.Dict[str, str]) -> None:
        """Initialize the EndpointsController.

        Args:
            labels: Labels to be added to created resources.
        """
        self._client = kubernetes.client.CoreV1Api()
        self._labels = labels

    @property
    def name(self) -> str:
        """Name of the resource: "endpoints".

        Returns:
            Name of the resource: "endpoints".
        """
        return "endpoints"

    @_map_k8s_auth_exception
    def gen_resource_from_definition(
        self, definition: IngressDefinition
    ) -> kubernetes.client.V1Endpoints:
        """Generate an endpoints resource from ingress definition.

        Args:
            definition: Ingress definition to use for generating the V1Endpoints resource.

        Returns:
            Generated endpoints resource.
        """
        return kubernetes.client.V1Endpoints(
            api_version="v1",
            kind="Endpoints",
            metadata=kubernetes.client.V1ObjectMeta(
                name=definition.k8s_service_name,
                labels=self._labels,
                namespace=definition.service_namespace,
            ),
            subsets=[
                kubernetes.client.V1EndpointSubset(
                    addresses=[
                        kubernetes.client.V1EndpointAddress(ip=endpoint)
                        for endpoint in definition.upstream_endpoints
                    ],
                    ports=[kubernetes.client.CoreV1EndpointPort(port=definition.service_port)],
                )
            ],
        )

    @_map_k8s_auth_exception
    def create_resource(self, namespace: str, body: kubernetes.client.V1Endpoints) -> None:
        """Create a new V1Endpoints resource in a given namespace.

        Args:
            namespace: The namespace in which to create the V1Endpoints resource.
            body: The V1Endpoints resource object to create.
        """
        self._client.create_namespaced_endpoints(namespace=namespace, body=body)

    @_map_k8s_auth_exception
    def patch_resource(
        self, namespace: str, name: str, body: kubernetes.client.V1Endpoints
    ) -> None:
        """Patch an existing V1Endpoints resource in a given namespace.

        Args:
            namespace: The namespace in which the V1Endpoints resource resides.
            name: The name of the V1Endpoints resource to patch.
            body: The modified V1Endpoints resource object.
        """
        self._client.patch_namespaced_endpoints(namespace=namespace, name=name, body=body)

    @_map_k8s_auth_exception
    def list_resource(
        self, namespace: str, label_selector: str
    ) -> typing.List[kubernetes.client.V1Endpoints]:
        """List V1Endpoints resources in a given namespace based on a label selector.

        Args:
            namespace: The namespace to list V1Endpoints resources from.
            label_selector: The label selector to filter V1Endpoints resources.

        Returns:
            A list of matched V1Endpoints resources.
        """
        return self._client.list_namespaced_endpoints(
            namespace=namespace, label_selector=label_selector
        ).items

    @_map_k8s_auth_exception
    def delete_resource(self, namespace: str, name: str) -> None:
        """Delete a V1Endpoints resource from a given namespace.

        Args:
            namespace: The namespace from which to delete the V1Endpoints resource.
            name: The name of the V1Endpoints resource to delete.
        """
        self._client.delete_namespaced_endpoints(namespace=namespace, name=name)


class EndpointSliceController(ResourceController[kubernetes.client.V1EndpointSlice]):
    """Kubernetes EndpointSlice resource controller."""

    def __init__(self, labels: typing.Dict[str, str]) -> None:
        """Initialize the EndpointSliceController.

        Args:
            labels: Label to be added to created resources.
        """
        self._labels = labels
        self._client = kubernetes.client.DiscoveryV1Api()
        self._beta_client = kubernetes.client.DiscoveryV1beta1Api()

    @property
    def name(self) -> str:
        """Returns "endpoint slice"."""
        return "endpoint slice"

    @_map_k8s_auth_exception
    def gen_resource_from_definition(
        self, definition: IngressDefinition
    ) -> kubernetes.client.V1EndpointSlice:
        """Generate a V1EndpointSlice resource from ingress definition.

        Args:
            definition: Ingress definition to use for generating the V1EndpointSlice resource.

        Returns:
            The generated V1EndpointSlice resource.
        """
        address_type = definition.upstream_endpoint_type
        return kubernetes.client.V1EndpointSlice(
            api_version="discovery.k8s.io/v1",
            kind="EndpointSlice",
            metadata=kubernetes.client.V1ObjectMeta(
                name=definition.k8s_endpoint_slice_name,
                namespace=definition.service_namespace,
                labels={
                    **self._labels,
                    "kubernetes.io/service-name": definition.k8s_service_name,
                },
            ),
            address_type=address_type,
            ports=[
                kubernetes.client.DiscoveryV1EndpointPort(
                    name=f"endpoint-tcp-{definition.service_port}",
                    port=definition.service_port,
                )
            ],
            endpoints=[
                kubernetes.client.V1Endpoint(
                    addresses=definition.upstream_endpoints,
                    conditions=kubernetes.client.V1EndpointConditions(ready=True, serving=True),
                )
            ],
        )

    @_map_k8s_auth_exception
    def create_resource(self, namespace: str, body: kubernetes.client.V1EndpointSlice) -> None:
        """Create a new V1EndpointSlice resource in a given namespace.

        Args:
            namespace: The namespace in which to create the V1EndpointSlice resource.
            body: The V1EndpointSlice resource object to create.
        """
        try:
            self._client.create_namespaced_endpoint_slice(namespace=namespace, body=body)
        except kubernetes.client.exceptions.ApiException as exc:
            if exc.status == 404:
                body.api_version = "discovery.k8s.io/v1beta1"
                self._beta_client.create_namespaced_endpoint_slice(namespace=namespace, body=body)
            else:
                raise

    @_map_k8s_auth_exception
    def patch_resource(
        self, namespace: str, name: str, body: kubernetes.client.V1EndpointSlice
    ) -> None:
        """Patch an existing V1EndpointSlice resource in a given namespace.

        Args:
            namespace: The namespace in which the V1EndpointSlice resource resides.
            name: The name of the V1EndpointSlice resource to patch.
            body: The modified V1EndpointSlice resource object.
        """
        try:
            self._client.patch_namespaced_endpoint_slice(namespace=namespace, name=name, body=body)
        except kubernetes.client.exceptions.ApiException as exc:
            if exc.status == 404:
                body.api_version = "discovery.k8s.io/v1beta1"
                self._beta_client.patch_namespaced_endpoint_slice(
                    namespace=namespace, name=name, body=body
                )
            else:
                raise

    @_map_k8s_auth_exception
    def list_resource(
        self, namespace: str, label_selector: str
    ) -> typing.List[kubernetes.client.V1EndpointSlice]:
        """List V1EndpointSlice resources in a given namespace based on a label selector.

        Args:
            namespace: The namespace to list V1EndpointSlice resources from.
            label_selector: The label selector to filter V1EndpointSlice resources.

        Returns:
            A list of matched V1EndpointSlice resources.
        """
        try:
            return self._client.list_namespaced_endpoint_slice(
                namespace=namespace, label_selector=label_selector
            ).items
        except kubernetes.client.exceptions.ApiException as exc:
            if exc.status == 404:
                return self._beta_client.list_namespaced_endpoint_slice(
                    namespace=namespace, label_selector=label_selector
                ).items
            raise

    @_map_k8s_auth_exception
    def delete_resource(self, namespace: str, name: str) -> None:
        """Delete a V1EndpointSlice resource from a given namespace.

        Args:
            namespace: The namespace from which to delete the V1EndpointSlice resource.
            name: The name of the V1EndpointSlice resource to delete.
        """
        try:
            self._client.delete_namespaced_endpoint_slice(namespace=namespace, name=name)
        except kubernetes.client.exceptions.ApiException as exc:
            if exc.status == 404:
                self._beta_client.delete_namespaced_endpoint_slice(namespace=namespace, name=name)
            else:
                raise


class ServiceController(ResourceController[kubernetes.client.V1Service]):
    """Kubernetes Service resource controller."""

    def __init__(self, labels: typing.Dict[str, str]) -> None:
        """Initialize the ServiceController.

        Args:
            labels: Labels to be added to created resources.
        """
        self._client = kubernetes.client.CoreV1Api()
        self._labels = labels

    @property
    def name(self) -> str:
        """Returns "service"."""
        return "service"

    @_map_k8s_auth_exception
    def gen_resource_from_definition(
        self, definition: IngressDefinition
    ) -> kubernetes.client.V1Service:
        """Generate a V1Service resource from ingress definition.

        Args:
            definition: Ingress definition to use for generating the V1Service resource.

        Returns:
            The generated V1Service resource.
        """
        spec = kubernetes.client.V1ServiceSpec(
            ports=[
                kubernetes.client.V1ServicePort(
                    name=f"tcp-{definition.service_port}",
                    port=definition.service_port,
                    target_port=definition.service_port,
                )
            ],
        )
        if not definition.use_endpoint_slice:
            spec.selector = {"app.kubernetes.io/name": definition.service_name}
        else:
            spec.cluster_ip = "None"
        return kubernetes.client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=kubernetes.client.V1ObjectMeta(
                name=definition.k8s_service_name,
                labels=self._labels,
                namespace=definition.service_namespace,
            ),
            spec=spec,
        )

    @_map_k8s_auth_exception
    def create_resource(self, namespace: str, body: kubernetes.client.V1Service) -> None:
        """Create a new V1Service resource in a given namespace.

        Args:
            namespace: The namespace in which to create the V1Service resource.
            body: The V1Service resource object to create.
        """
        self._client.create_namespaced_service(namespace=namespace, body=body)

    @_map_k8s_auth_exception
    def patch_resource(self, namespace: str, name: str, body: kubernetes.client.V1Service) -> None:
        """Patch an existing V1Service resource in a given namespace.

        Args:
            namespace: The namespace in which the V1Service resource resides.
            name: The name of the V1Service resource to patch.
            body: The modified V1Service resource object.
        """
        self._client.patch_namespaced_service(namespace=namespace, name=name, body=body)

    @_map_k8s_auth_exception
    def list_resource(
        self, namespace: str, label_selector: str
    ) -> typing.List[kubernetes.client.V1Service]:
        """List V1Service resources in a given namespace based on a label selector.

        Args:
            namespace: The namespace to list V1Service resources from.
            label_selector: The label selector to filter V1Service resources.

        Returns:
            A list of matched V1Service resources.
        """
        return self._client.list_namespaced_service(
            namespace=namespace, label_selector=label_selector
        ).items

    @_map_k8s_auth_exception
    def delete_resource(self, namespace: str, name: str) -> None:
        """Delete a V1Service resource from a given namespace.

        Args:
            namespace: The namespace from which to delete the V1Service resource.
            name: The name of the V1Service resource to delete.
        """
        self._client.delete_namespaced_service(namespace=namespace, name=name)


class IngressController(ResourceController[kubernetes.client.V1Ingress]):
    """Kubernetes Ingress resource controller."""

    def __init__(
        self,
        labels: typing.Dict[str, str],
    ) -> None:
        """Initialize the IngressController.

        Args:
            labels: Label to be added to created resources.
        """
        self._client = kubernetes.client.NetworkingV1Api()
        self._labels = labels

    @property
    def name(self) -> str:
        """Returns "ingress"."""
        return "ingress"

    def _look_up_and_set_ingress_class(
        self, ingress_class: typing.Optional[str], body: kubernetes.client.V1Ingress
    ) -> None:
        """Set the configured ingress class, otherwise the cluster's default ingress class.

        Args:
            ingress_class: The desired ingress class name.
            body: The Ingress resource object.
        """
        if not ingress_class:
            defaults = [
                item.metadata.name
                for item in self._client.list_ingress_class().items
                if item.metadata.annotations.get("ingressclass.kubernetes.io/is-default-class")
                == "true"
            ]

            if not defaults:
                logger.warning("Cluster has no default ingress class defined")
                return

            if len(defaults) > 1:
                default_ingress = " ".join(sorted(defaults))
                msg = "Multiple default ingress classes defined, declining to choose between them."
                logger.warning(
                    "%s. They are: %s",
                    msg,
                    default_ingress,
                )
                return

            ingress_class = defaults[0]
            logger.info("Using ingress class %s as it is the cluster's default", ingress_class)

        body.spec.ingress_class_name = ingress_class

    @_map_k8s_auth_exception
    def gen_resource_from_definition(
        self, definition: IngressDefinition
    ) -> kubernetes.client.V1Ingress:
        """Generate a V1Ingress resource from ingress definition.

        Args:
            definition: Ingress definition to use for generating the V1Ingress resource.

        Returns:
            A V1Ingress resource based on provided definition.
        """
        ingress_paths = [
            kubernetes.client.V1HTTPIngressPath(
                path=path,
                path_type="Prefix",
                backend=kubernetes.client.V1IngressBackend(
                    service=kubernetes.client.V1IngressServiceBackend(
                        name=definition.k8s_service_name,
                        port=kubernetes.client.V1ServiceBackendPort(
                            number=int(definition.service_port),
                        ),
                    ),
                ),
            )
            for path in definition.path_routes
        ]

        hostnames = [definition.service_hostname]
        hostnames.extend(definition.additional_hostnames)
        ingress_rules = [
            kubernetes.client.V1IngressRule(
                host=hostname,
                http=kubernetes.client.V1HTTPIngressRuleValue(paths=ingress_paths),
            )
            for hostname in hostnames
        ]
        spec = kubernetes.client.V1IngressSpec(rules=ingress_rules)

        annotations = {
            "nginx.ingress.kubernetes.io/proxy-body-size": definition.max_body_size,
            "nginx.ingress.kubernetes.io/proxy-read-timeout": definition.proxy_read_timeout,
            "nginx.ingress.kubernetes.io/backend-protocol": definition.backend_protocol,
        }
        if definition.limit_rps:
            annotations["nginx.ingress.kubernetes.io/limit-rps"] = definition.limit_rps
            if definition.limit_whitelist:
                annotations[
                    "nginx.ingress.kubernetes.io/limit-whitelist"
                ] = definition.limit_whitelist
        if definition.owasp_modsecurity_crs:
            annotations["nginx.ingress.kubernetes.io/enable-modsecurity"] = "true"
            annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"] = "true"
            sec_rule_engine = f"SecRuleEngine On\n{definition.owasp_modsecurity_custom_rules}"
            nginx_modsec_file = "/etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf"
            annotations[
                "nginx.ingress.kubernetes.io/modsecurity-snippet"
            ] = f"{sec_rule_engine}\nInclude {nginx_modsec_file}"
        if definition.retry_errors:
            annotations[
                "nginx.ingress.kubernetes.io/proxy-next-upstream"
            ] = definition.retry_errors
        if definition.rewrite_enabled:
            annotations["nginx.ingress.kubernetes.io/rewrite-target"] = definition.rewrite_target
        if definition.session_cookie_max_age:
            annotations["nginx.ingress.kubernetes.io/affinity"] = "cookie"
            annotations["nginx.ingress.kubernetes.io/affinity-mode"] = "balanced"
            annotations["nginx.ingress.kubernetes.io/session-cookie-change-on-failure"] = "true"
            annotations["nginx.ingress.kubernetes.io/session-cookie-max-age"] = str(
                definition.session_cookie_max_age
            )
            annotations[
                "nginx.ingress.kubernetes.io/session-cookie-name"
            ] = f"{definition.service_name.upper()}_AFFINITY"
            annotations["nginx.ingress.kubernetes.io/session-cookie-samesite"] = "Lax"
        if definition.tls_secret_name:
            spec.tls = [
                kubernetes.client.V1IngressTLS(
                    hosts=[definition.service_hostname],
                    secret_name=definition.tls_secret_name,
                ),
            ]
        else:
            annotations["nginx.ingress.kubernetes.io/ssl-redirect"] = "false"
        if definition.whitelist_source_range:
            annotations[
                "nginx.ingress.kubernetes.io/whitelist-source-range"
            ] = definition.whitelist_source_range

        ingress = kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=definition.k8s_ingress_name,
                namespace=definition.service_namespace,
                annotations=annotations,
                labels=self._labels,
            ),
            spec=spec,
        )
        self._look_up_and_set_ingress_class(ingress_class=definition.ingress_class, body=ingress)
        return ingress

    @_map_k8s_auth_exception
    def create_resource(self, namespace: str, body: kubernetes.client.V1Ingress) -> None:
        """Create a new V1Ingress resource in a given namespace.

        Args:
            namespace: The namespace in which to create the V1Ingress resource.
            body: The V1Ingress resource object to create.
        """
        self._client.create_namespaced_ingress(namespace=namespace, body=body)

    @_map_k8s_auth_exception
    def patch_resource(self, namespace: str, name: str, body: kubernetes.client.V1Ingress) -> None:
        """Replace an existing V1Ingress resource in a given namespace.

        Args:
            namespace: The namespace in which the V1Ingress resource resides.
            name: The name of the V1Ingress resource to replace.
            body: The modified V1Ingress resource object.
        """
        self._client.replace_namespaced_ingress(namespace=namespace, name=name, body=body)

    @_map_k8s_auth_exception
    def list_resource(
        self, namespace: str, label_selector: str
    ) -> typing.List[kubernetes.client.V1Ingress]:
        """List V1Ingress resources in a given namespace based on a label selector.

        Args:
            namespace: The namespace to list V1Ingress resources from.
            label_selector: The label selector to filter V1Ingress resources.

        Returns:
            A list of matched V1Ingress resources.
        """
        return self._client.list_namespaced_ingress(
            namespace=namespace, label_selector=label_selector
        ).items

    @_map_k8s_auth_exception
    def delete_resource(self, namespace: str, name: str) -> None:
        """Delete a V1Ingress resource from a given namespace.

        Args:
            namespace: The namespace from which to delete the V1Ingress resource.
            name: The name of the V1Ingress resource to delete.
        """
        self._client.delete_namespaced_ingress(namespace=namespace, name=name)
