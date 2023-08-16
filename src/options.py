# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""nginx-ingress-integrator ingress option."""


import ipaddress
import json
from typing import Any, Generator, List, cast

import kubernetes.client
from ops.model import Application, ConfigData, Model, Relation

from consts import _INGRESS_SUB_REGEX, BOOLEAN_CONFIG_FIELDS, CREATED_BY_LABEL
from exceptions import InvalidIngressOptionError


class _ConfigOrRelation:
    """Class containing data from the Charm configuration, or from a relation."""

    def __init__(
        self,
        model: Model,
        config: ConfigData,
        relation: Relation,
    ) -> None:
        """Create a _ConfigOrRelation Object.

        Args:
            model: The charm model.
            config: The charm's configuration.
            relation: One of the charm's relations, if any.
        """
        super().__init__()
        self.model = model
        self.config = config
        self.relation = relation

    def _get_config(self, field: Any) -> Any:
        """Get data from config.

        Args:
            field: Config field.

        Returns:
            The field's content.
        """
        # Config fields with a default of None don't appear in the dict
        config_data = self.config.get(field, None)
        # A value of False is valid in these fields, so check it's not a null-value instead
        if field in BOOLEAN_CONFIG_FIELDS and (config_data is not None and config_data != ""):
            return config_data
        if config_data:
            return config_data

        return None

    def _get_relation(self, field: Any) -> Any:
        """Get data from the relation, if any.

        Args:
            field: Relation field.

        Returns:
            The field's content.
        """
        return self.relation.data[cast(Application, self.relation.app)].get(field)

    def _get_config_or_relation_data(self, field: Any, fallback: Any) -> Any:
        """Get data from config or the ingress relation, in that order.

        Args:
            field: Config or relation field.
            fallback: Value to return if the field is not found.

        Returns:
            The field's content or the fallback value if no field is found.
        """
        data = self._get_config(field)
        if data is not None:
            return data

        data = self._get_relation(field)
        if data is not None:
            return data

        return fallback

    def _get_relation_data_or_config(self, field: Any, fallback: Any) -> Any:
        """Get data from the ingress relation or config, in that order.

        Args:
            field: Config or relation field.
            fallback: Value to return if the field is not found.

        Returns:
            The field's content or the fallback value if no field is found.
        """
        data = self._get_relation(field)
        if data is not None:
            return data

        data = self._get_config(field)
        if data is not None:
            return data

        return fallback

    @property
    def additional_hostnames(self) -> Generator[str, None, None]:
        """Return a list with additional hostnames.

        Returns:
            The additional hostnames set by configuration already split by comma.
        """
        additional_hostnames = self._get_config_or_relation_data("additional-hostnames", "")
        yield from filter(None, additional_hostnames.split(","))

    @property
    def backend_protocol(self) -> str:
        """Return the backend-protocol to use for k8s ingress."""
        return self._get_config_or_relation_data("backend-protocol", "HTTP").upper()

    @property
    def k8s_endpoint_slice_name(self) -> str:
        """Return the endpoint slice name for the use creating a k8s endpoint slice."""
        # endpoint slice name must be the same as service name
        # to be detected by nginx ingress controller
        return self.k8s_service_name

    @property
    def k8s_service_name(self) -> str:
        """Return a service name for the use creating a k8s service."""
        # Avoid collision with service name created by Juju. Currently
        # Juju creates a K8s service listening on port 65535/TCP so we
        # need to create a separate one.
        return f"relation-{self.relation.id}-{self.service_name}-service"

    @property
    def k8s_ingress_name(self) -> str:
        """Return an ingress name for use creating a k8s ingress."""
        # If there are 2 or more services configured to use the same service-hostname, the
        # controller nginx/nginx-ingress requires them to be in the same Kubernetes Ingress object.
        # Otherwise, Ingress will be served for only one of the services.
        # Because of this, we'll have to group all ingresses into the same Kubernetes Resource
        # based on their requested service-hostname.
        svc_hostname = self._get_config_or_relation_data("service-hostname", "")
        ingress_name = _INGRESS_SUB_REGEX.sub("-", svc_hostname)
        return f"relation-{self.relation.id}-{ingress_name}-ingress"

    @property
    def _limit_rps(self) -> str:
        """Return limit-rps value from config or relation."""
        limit_rps = self._get_config_or_relation_data("limit-rps", 0)
        if limit_rps:
            return str(limit_rps)
        # Don't return "0" which would evaluate to True.
        return ""

    @property
    def _limit_whitelist(self) -> str:
        """Return the limit-whitelist value from config or relation."""
        return self._get_config_or_relation_data("limit-whitelist", "")

    @property
    def _max_body_size(self) -> str:
        """Return the max-body-size to use for k8s ingress."""
        max_body_size = self._get_config_or_relation_data("max-body-size", 0)
        return f"{max_body_size}m"

    @property
    def _owasp_modsecurity_crs(self) -> bool:
        """Return a boolean indicating whether OWASP ModSecurity CRS is enabled."""
        value = self._get_config_or_relation_data("owasp-modsecurity-crs", False)
        return str(value).lower() == "true"

    @property
    def _owasp_modsecurity_custom_rules(self) -> str:
        r"""Return the owasp-modsecurity-custom-rules value from config or relation.

        Since when setting the config via CLI or via YAML file, the new line character ('\n')
        is escaped ('\\n') we need to replace it for a new line character.
        """
        return self._get_config_or_relation_data("owasp-modsecurity-custom-rules", "").replace(
            "\\n", "\n"
        )

    @property
    def _proxy_read_timeout(self) -> str:
        """Return the proxy-read-timeout to use for k8s ingress."""
        proxy_read_timeout = self._get_config_or_relation_data("proxy-read-timeout", 60)
        return f"{proxy_read_timeout}"

    @property
    def _rewrite_enabled(self) -> bool:
        """Return whether rewriting should be enabled from config or relation."""
        value = self._get_config_or_relation_data("rewrite-enabled", True)
        # config data is typed, relation data is a string
        # Convert to string, then compare to a known value.
        return str(value).lower() == "true"

    @property
    def _rewrite_target(self) -> Any:
        """Return the rewrite target from config or relation."""
        return self._get_config_or_relation_data("rewrite-target", "/")

    @property
    def service_namespace(self) -> Any:
        """Return the namespace to operate on."""
        if self.is_ingress_relation:
            return json.loads(
                self._get_config_or_relation_data("model", json.dumps(self.model.name))
            )
        return self._get_config_or_relation_data("service-namespace", self.model.name)

    @property
    def _retry_errors(self) -> str:
        """Return the retry-errors setting from config or relation."""
        retry = self._get_config_or_relation_data("retry-errors", "")
        if not retry:
            return ""
        # See http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream.
        accepted_values = [
            "error",
            "timeout",
            "invalid_header",
            "http_500",
            "http_502",
            "http_503",
            "http_504",
            "http_403",
            "http_404",
            "http_429",
            "non_idempotent",
            "off",
        ]
        return " ".join([x.strip() for x in retry.split(",") if x.strip() in accepted_values])

    @property
    def service_hostname(self) -> Any:
        """Return the hostname for the service we're connecting to."""
        return self._get_config_or_relation_data("service-hostname", "")

    @property
    def service_name(self) -> Any:
        """Return the name of the service we're connecting to."""
        if self.is_ingress_relation:
            return json.loads(self._get_relation_data_or_config("name", '""'))
        return self._get_relation_data_or_config("service-name", "")

    @property
    def service_port(self) -> int:
        """Return the port for the service we're connecting to."""
        if self.is_ingress_relation:
            port = self._get_relation_data_or_config("port", 0)
        else:
            port = self._get_relation_data_or_config("service-port", 0)
        return int(port)

    @property
    def _path_routes(self) -> Any:
        """Return the path routes to use for the k8s ingress."""
        if self.is_ingress_relation:
            return self._get_config_or_relation_data(
                "path-routes", f"/{self.service_namespace}-{self.service_name}"
            ).split(",")
        return self._get_config_or_relation_data("path-routes", "/").split(",")

    @property
    def _session_cookie_max_age(self) -> Any:
        """Return the session-cookie-max-age to use for k8s ingress."""
        session_cookie_max_age = self._get_config_or_relation_data("session-cookie-max-age", 0)
        if session_cookie_max_age:
            return str(session_cookie_max_age)
        # Don't return "0" which would evaluate to True.
        return ""

    @property
    def _tls_secret_name(self) -> Any:
        """Return the tls-secret-name to use for k8s ingress (if any)."""
        return self._get_config_or_relation_data("tls-secret-name", "")

    @property
    def _whitelist_source_range(self) -> Any:
        """Return the whitelist-source-range config option."""
        return self._get_config("whitelist-source-range")

    @property
    def upstream_endpoints(self) -> List[str]:
        """Return the ingress upstream endpoint ip addresses, only in ingress v2 relation."""
        if self.use_endpoint_slice:
            endpoints = [self.relation.data[unit].get("ip") for unit in self.relation.units]
            endpoints = [json.loads(ip) for ip in endpoints if ip]
            return endpoints
        return []

    @property
    def use_endpoint_slice(self) -> bool:
        """Check if the ingress need to use endpoint slice."""
        return self.is_ingress_relation

    @property
    def is_ingress_relation(self) -> bool:
        """Check if the relation is connected via ingress relation endpoint."""
        return self.relation.name == "ingress"

    def get_k8s_endpoint_slice(self, label: str) -> kubernetes.client.V1EndpointSlice:
        """Get a K8s endpoint slice definition.

        Args:
            label: Custom label assigned to every service.

        Returns:
            A k8s service definition.

        Raises:
            InvalidIngressOptionError: if the upstream endpoints are invalid.
        """
        address_types = []
        for address in self.upstream_endpoints:
            address = address.strip()
            try:
                ipaddress.IPv6Address(address)
                address_types.append("IPv6")
                continue
            except ValueError:
                pass
            try:
                ipaddress.IPv4Address(address)
                address_types.append("IPv4")
                continue
            except ValueError:
                pass
            address_types.append("UNKNOWN")
        if not all(t == "IPv4" for t in address_types) or all(t == "IPv6" for t in address_types):
            raise InvalidIngressOptionError(
                "invalid ingress relation data, mixed or unknown IP types"
            )
        address_type = address_types[0]
        return kubernetes.client.V1EndpointSlice(
            api_version="discovery.k8s.io/v1",
            kind="EndpointSlice",
            metadata=kubernetes.client.V1ObjectMeta(
                name=self.k8s_endpoint_slice_name,
                labels={
                    CREATED_BY_LABEL: label,
                    "kubernetes.io/service-name": self.k8s_service_name,
                },
            ),
            address_type=address_type,
            ports=[
                kubernetes.client.DiscoveryV1EndpointPort(
                    name=f"endpoint-tcp-{self.service_port}",
                    port=self.service_port,
                )
            ],
            endpoints=[
                kubernetes.client.V1Endpoint(
                    addresses=self.upstream_endpoints,
                    conditions=kubernetes.client.V1EndpointConditions(ready=True, serving=True),
                )
            ],
        )

    def get_k8s_service(self, label: str) -> kubernetes.client.V1Service:
        """Get a K8s service definition.

        Args:
            label: Custom label assigned to every service.

        Returns:
            A k8s service definition.
        """
        spec = kubernetes.client.V1ServiceSpec(
            ports=[
                kubernetes.client.V1ServicePort(
                    name=f"tcp-{self.service_port}",
                    port=self.service_port,
                    target_port=self.service_port,
                )
            ],
        )
        if not self.use_endpoint_slice:
            spec.selector = {"app.kubernetes.io/name": self.service_name}
        else:
            spec.cluster_ip = "None"
        return kubernetes.client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=kubernetes.client.V1ObjectMeta(
                name=self.k8s_service_name, labels={CREATED_BY_LABEL: label}
            ),
            spec=spec,
        )

    def get_k8s_ingress(self, label: str) -> kubernetes.client.V1Ingress:
        """Get a K8s ingress definition.

        Args:
            label: Custom label assigned to every ingress.

        Returns:
            A k8s Ingress definition.
        """
        ingress_paths = [
            kubernetes.client.V1HTTPIngressPath(
                path=path,
                path_type="Prefix",
                backend=kubernetes.client.V1IngressBackend(
                    service=kubernetes.client.V1IngressServiceBackend(
                        name=self.k8s_service_name,
                        port=kubernetes.client.V1ServiceBackendPort(
                            number=int(self.service_port),
                        ),
                    ),
                ),
            )
            for path in self._path_routes
        ]

        hostnames = [self.service_hostname]
        hostnames.extend(self.additional_hostnames)
        ingress_rules = [
            kubernetes.client.V1IngressRule(
                host=hostname,
                http=kubernetes.client.V1HTTPIngressRuleValue(paths=ingress_paths),
            )
            for hostname in hostnames
        ]
        spec = kubernetes.client.V1IngressSpec(rules=ingress_rules)

        annotations = {
            "nginx.ingress.kubernetes.io/proxy-body-size": self._max_body_size,
            "nginx.ingress.kubernetes.io/proxy-read-timeout": self._proxy_read_timeout,
            "nginx.ingress.kubernetes.io/backend-protocol": self.backend_protocol,
        }
        if self._limit_rps:
            annotations["nginx.ingress.kubernetes.io/limit-rps"] = self._limit_rps
            if self._limit_whitelist:
                annotations["nginx.ingress.kubernetes.io/limit-whitelist"] = self._limit_whitelist
        if self._owasp_modsecurity_crs:
            annotations["nginx.ingress.kubernetes.io/enable-modsecurity"] = "true"
            annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"] = "true"
            sec_rule_engine = f"SecRuleEngine On\n{self._owasp_modsecurity_custom_rules}"
            nginx_modsec_file = "/etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf"
            annotations[
                "nginx.ingress.kubernetes.io/modsecurity-snippet"
            ] = f"{sec_rule_engine}\nInclude {nginx_modsec_file}"
        if self._retry_errors:
            annotations["nginx.ingress.kubernetes.io/proxy-next-upstream"] = self._retry_errors
        if self._rewrite_enabled:
            annotations["nginx.ingress.kubernetes.io/rewrite-target"] = self._rewrite_target
        if self._session_cookie_max_age:
            annotations["nginx.ingress.kubernetes.io/affinity"] = "cookie"
            annotations["nginx.ingress.kubernetes.io/affinity-mode"] = "balanced"
            annotations["nginx.ingress.kubernetes.io/session-cookie-change-on-failure"] = "true"
            annotations[
                "nginx.ingress.kubernetes.io/session-cookie-max-age"
            ] = self._session_cookie_max_age
            annotations[
                "nginx.ingress.kubernetes.io/session-cookie-name"
            ] = f"{self.service_name.upper()}_AFFINITY"
            annotations["nginx.ingress.kubernetes.io/session-cookie-samesite"] = "Lax"
        if self._tls_secret_name:
            spec.tls = [
                kubernetes.client.V1IngressTLS(
                    hosts=[self.service_hostname],
                    secret_name=self._tls_secret_name,
                ),
            ]
        else:
            annotations["nginx.ingress.kubernetes.io/ssl-redirect"] = "false"
        if self._whitelist_source_range:
            annotations[
                "nginx.ingress.kubernetes.io/whitelist-source-range"
            ] = self._whitelist_source_range

        return kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=self.k8s_ingress_name,
                annotations=annotations,
                labels={CREATED_BY_LABEL: label},
            ),
            spec=spec,
        )
