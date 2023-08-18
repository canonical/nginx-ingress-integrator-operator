#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=protected-access,too-few-public-methods,too-many-lines

"""Nginx-ingress-integrator charm file."""

import logging
import re
import time
import typing
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import kubernetes.client
import ops
from charms.nginx_ingress_integrator.v0.ingress import (
    RELATION_INTERFACES_MAPPINGS,
    REQUIRED_INGRESS_RELATION_FIELDS,
    IngressCharmEvents,
    IngressProvides,
)
from charms.nginx_ingress_integrator.v0.nginx_route import provide_nginx_route
from ops.charm import CharmBase, HookEvent, StartEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, ConfigData, Model, Relation, WaitingStatus

from helpers import invalid_hostname_check, is_backend_protocol_valid

LOGGER = logging.getLogger(__name__)
_INGRESS_SUB_REGEX = re.compile("[^0-9a-zA-Z]")
BOOLEAN_CONFIG_FIELDS = ["rewrite-enabled"]
# We set this value to be unique for this deployed juju application
# so we can use it to identify resources created by this charm
CREATED_BY_LABEL = "nginx-ingress-integrator.charm.juju.is/managed-by"
REPORT_INTERVAL_COUNT = 100
INVALID_HOSTNAME_MSG = (
    "Invalid ingress hostname. The hostname must consist of lower case "
    "alphanumeric characters, '-' or '.'."
)
INVALID_BACKEND_PROTOCOL_MSG = (
    "Invalid backend protocol. Valid values: HTTP, HTTPS, GRPC, GRPCS, AJP, FCGI"
)


def _report_interval_count() -> int:
    """Set interval count for report ingress.

    Returns:
         Interval count
    """
    return REPORT_INTERVAL_COUNT


class ConflictingAnnotationsError(Exception):
    """Custom error that indicates conflicting annotations."""


class ConflictingRoutesError(Exception):
    """Custom error that indicates conflicting routes."""


class InvalidBackendProtocolError(Exception):
    """Custom error that indicates invalid backend protocol."""


class InvalidHostnameError(Exception):
    """Custom error that indicates invalid hostnames."""


class _ConfigOrRelation:
    """Class containing data from the Charm configuration, or from a relation."""

    def __init__(
        self,
        model: Model,
        config: Union[ConfigData, Dict],
        relation: Optional[Relation],
        multiple_relations: bool,
    ) -> None:
        """Create a _ConfigOrRelation Object.

        Args:
            model: The charm model.
            config: The charm's configuration.
            relation: One of the charm's relations, if any.
            multiple_relations: If the charm has more than one relation.
        """
        super().__init__()
        self.model = model
        self.config = config
        self.relation = relation
        self.multiple_relations = multiple_relations

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
        if self.relation:
            try:
                # We want to prioritise relation-interfaces data if we have it.
                assert self.relation.app is not None  # nosec
                if field in RELATION_INTERFACES_MAPPINGS:
                    new_field = RELATION_INTERFACES_MAPPINGS[field]
                    try:
                        return self.relation.data[self.relation.app][new_field]
                    except KeyError:
                        return self.relation.data[self.relation.app][field]
                else:
                    return self.relation.data[self.relation.app][field]
            except KeyError:
                # Our relation isn't passing the information we're querying.
                return None
        return None

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
    def _additional_hostnames(self) -> Generator[str, None, None]:
        """Return a list with additional hostnames.

        Returns:
            The additional hostnames set by configuration already split by comma.
        """
        additional_hostnames = self._get_config_or_relation_data("additional-hostnames", "")
        yield from filter(None, additional_hostnames.split(","))

    @property
    def _backend_protocol(self) -> str:
        """Return the backend-protocol to use for k8s ingress."""
        return self._get_config_or_relation_data("backend-protocol", "HTTP").upper()

    @property
    def _k8s_service_name(self) -> str:
        """Return a service name for the use creating a k8s service."""
        # Avoid collision with service name created by Juju. Currently
        # Juju creates a K8s service listening on port 65535/TCP so we
        # need to create a separate one.
        return f"{self._service_name}-service"

    @property
    def _ingress_name(self) -> str:
        """Return an ingress name for use creating a k8s ingress."""
        # If there are 2 or more services configured to use the same service-hostname, the
        # controller nginx/nginx-ingress requires them to be in the same Kubernetes Ingress object.
        # Otherwise, Ingress will be served for only one of the services.
        # Because of this, we'll have to group all ingresses into the same Kubernetes Resource
        # based on their requested service-hostname.
        svc_hostname = self._get_config_or_relation_data("service-hostname", "")
        ingress_name = _INGRESS_SUB_REGEX.sub("-", svc_hostname)
        return f"{ingress_name}-ingress"

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
    def _namespace(self) -> Any:
        """Return the namespace to operate on."""
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
    def _service_hostname(self) -> Any:
        """Return the hostname for the service we're connecting to."""
        return self._get_config_or_relation_data("service-hostname", "")

    @property
    def _service_name(self) -> Any:
        """Return the name of the service we're connecting to."""
        # NOTE: If the charm has multiple relations, use the service name given by the relation
        # in order to avoid service name conflicts.
        if self.multiple_relations:
            return self._get_relation_data_or_config("service-name", "")
        return self._get_config_or_relation_data("service-name", "")

    @property
    def _service_port(self) -> int:
        """Return the port for the service we're connecting to."""
        # NOTE: If the charm has multiple relations, use the service port given by the relation.
        if self.multiple_relations:
            return int(self._get_relation_data_or_config("service-port", 0))
        return int(self._get_relation_data_or_config("service-port", 0))

    @property
    def _path_routes(self) -> Any:
        """Return the path routes to use for the k8s ingress."""
        # NOTE: If the charm has multiple relations, use the path routes given by the relation
        # in order to avoid same route conflicts.
        if self.multiple_relations:
            return self._get_relation_data_or_config("path-routes", "/").split(",")
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

    def _get_k8s_service(self, label: str) -> kubernetes.client.V1Service:
        """Get a K8s service definition.

        Args:
            label: Custom label assigned to every service.

        Returns:
            A k8s service definition.
        """
        return kubernetes.client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=kubernetes.client.V1ObjectMeta(
                name=self._k8s_service_name, labels={CREATED_BY_LABEL: label}
            ),
            spec=kubernetes.client.V1ServiceSpec(
                selector={"app.kubernetes.io/name": self._service_name},
                ports=[
                    kubernetes.client.V1ServicePort(
                        name=f"tcp-{self._service_port}",
                        port=self._service_port,
                        target_port=self._service_port,
                    )
                ],
            ),
        )

    def _get_k8s_ingress(self, label: str) -> kubernetes.client.V1Ingress:
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
                        name=self._k8s_service_name,
                        port=kubernetes.client.V1ServiceBackendPort(
                            number=int(self._service_port),
                        ),
                    ),
                ),
            )
            for path in self._path_routes
        ]

        hostnames = [self._service_hostname]
        hostnames.extend(self._additional_hostnames)
        ingress_rules = [
            kubernetes.client.V1IngressRule(
                host=hostname,
                http=kubernetes.client.V1HTTPIngressRuleValue(paths=ingress_paths),
            )
            for hostname in hostnames
        ]
        spec = kubernetes.client.V1IngressSpec(rules=ingress_rules)

        annotations = {"nginx.ingress.kubernetes.io/proxy-body-size": self._max_body_size}
        annotations["nginx.ingress.kubernetes.io/proxy-read-timeout"] = self._proxy_read_timeout
        annotations["nginx.ingress.kubernetes.io/backend-protocol"] = self._backend_protocol
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
            ] = f"{self._service_name.upper()}_AFFINITY"
            annotations["nginx.ingress.kubernetes.io/session-cookie-samesite"] = "Lax"
        if self._tls_secret_name:
            spec.tls = [
                kubernetes.client.V1IngressTLS(
                    hosts=[self._service_hostname],
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
                name=self._ingress_name, annotations=annotations, labels={CREATED_BY_LABEL: label}
            ),
            spec=spec,
        )


class NginxIngressCharm(CharmBase):
    """Charm the service.

    Attrs:
        _authed: If the charm is authed or not
        on: Ingress charm events to handle.
    """

    _authed = False
    on = IngressCharmEvents()

    def __init__(self, *args) -> None:  # type: ignore[no-untyped-def]
        """Init method for the class.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
        """
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed_with_warning)
        self.framework.observe(self.on.describe_ingresses_action, self._describe_ingresses_action)
        self.framework.observe(self.on.start, self._on_start)

        # 'ingress' relation handling.
        self.ingress = IngressProvides(self)
        # When the 'ingress' is ready to configure, do so.
        self.framework.observe(self.on.ingress_available, self._on_config_changed_with_warning)
        self.framework.observe(self.on.ingress_broken, self._on_ingress_broken)

        provide_nginx_route(
            charm=self,
            on_nginx_route_available=self._on_config_changed,
            on_nginx_route_broken=self._on_ingress_broken,
        )

    def _on_config_changed_with_warning(self, event: Any) -> None:
        """Handle the ingress relation available event.

        The same functionality as _on_config_changed, but will add warning message if there are
        applications connected via ingress relation.

        Args:
            event: not used.
        """
        self._on_config_changed(event)
        status = self.unit.status
        connected_apps = {
            relation.app.name
            for relation in self.model.relations["ingress"]
            if relation.app is not None
        }
        if connected_apps:
            connected_app_names = ", ".join(sorted(connected_apps))
            warning = (
                f"app [{connected_app_names}] connected via deprecated ingress relation, "
                f"please update to nginx-route relation; {status.message}"
            )
            self.unit.status = status.from_name(status.name, warning)

    def _on_start(self, _: StartEvent) -> None:
        """Handle the start event."""
        # We need to set ActiveStatus here because this is a workload-less
        # charm, so there's no pebble-ready event to react to. This means this
        # is the only event (outside of update-status) that is fired if a pod is
        # restarted by the k8s cluster. If we don't do anything here the charm
        # would remain in maintenance status.
        self.unit.status = ActiveStatus()

    @staticmethod
    def _gen_relation_dedup_key(relation: Relation) -> typing.Tuple[str, ...]:
        """Generate a key from the given relation to detect duplicates in _deduped_relations.

        Args:
            relation: the given relation object.

        Returns: The key as a tuple of strings.

        Raises:
            RuntimeError: if the remote application is unknown.
        """
        app = relation.app
        if not app:
            raise RuntimeError(f"can't retrieve remote application from relation {relation}")
        data = relation.data[app]
        return (
            data.get("service-hostname"),
            data.get("service-name"),
            data.get("service-model"),
            data.get("service-port"),
            app.name,
        )

    def _deduped_relations(self) -> Tuple[ops.Relation, ...]:
        """Return a relation list with duplicates removed.

        Relations are considered duplicated if they meet the following criteria:
        1. Two are connected via the legacy ingress and the nginx-route relation endpoint
        2. Two share the same 4-tuple (service-hostname, service-name, service-model, service-port)
        3. Both relations have the same remote application.

        In the case of duplicates, the relation connected via legacy ingress is removed.

        Returns:
            A relation list with duplicates removed.
        """
        nginx_route_relations = [
            r for r in self.model.relations["nginx-route"] if r.app is not None
        ]
        ingress_relations = [r for r in self.model.relations["ingress"] if r.app is not None]
        nginx_route_relation_keys = set(
            self._gen_relation_dedup_key(r) for r in nginx_route_relations
        )
        dedup_ingress_relations = []
        for relation in ingress_relations:
            if self._gen_relation_dedup_key(relation) in nginx_route_relation_keys:
                LOGGER.warning(
                    "legacy ingress relation from app %s is shadowed by nginx-route relation",
                    relation.app,
                )
                continue
            dedup_ingress_relations.append(relation)
        return tuple(nginx_route_relations + dedup_ingress_relations)

    @property
    def _all_config_or_relations(self) -> Any:
        """Get all configuration and relation data.

        Returns:
            All configuration and relation data.
        """
        all_relations = self._deduped_relations()
        if not all_relations:
            all_relations = (None,)  # type: ignore[assignment]
        multiple_rels = self._multiple_relations
        return [
            _ConfigOrRelation(self.model, self.config, relation, multiple_rels)
            for relation in all_relations
        ]

    @property
    def _multiple_relations(self) -> bool:
        """Check if we're related to multiple applications.

        Returns:
            if we're related to multiple applications or not.
        """
        return len(self._deduped_relations()) > 1

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
        return self._all_config_or_relations[0]._namespace

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

    def _report_service_ips(self) -> List[str]:
        """Report on service IP(s) and return a list of them.

        Returns:
            A list of service IPs.
        """
        api = self._core_v1_api()
        services = api.list_namespaced_service(  # type: ignore[attr-defined]
            namespace=self._namespace
        )
        all_k8s_service_names = [rel._k8s_service_name for rel in self._all_config_or_relations]
        return [
            x.spec.cluster_ip for x in services.items if x.metadata.name in all_k8s_service_names
        ]

    def _report_ingress_ips(self) -> List[str]:
        """Report on ingress IP(s) and return a list of them.

        Returns:
            A list of Ingress IPs.
        """
        api = self._networking_v1_api()
        # Wait up to `interval * count` seconds for ingress IPs.
        count, interval = _report_interval_count(), 1
        for _ in range(count):
            ingresses = api.list_namespaced_ingress(  # type: ignore[attr-defined]
                namespace=self._namespace
            )
            try:
                ips = [x.status.load_balancer.ingress[0].ip for x in ingresses.items]
            except TypeError:
                # We have no IPs yet.
                ips = []
            if ips:
                break
            LOGGER.info("Sleeping for %s seconds to wait for ingress IP", interval)
            time.sleep(interval)
        return ips

    def _has_required_fields(self, conf_or_rel: _ConfigOrRelation) -> bool:
        """Check if the given config or relation has the required fields set.

        Args:
            conf_or_rel: Ingress configuration or relation class.

        Returns:
            If the config or relation class has all required fields or not.
        """
        # We use the same names in _ConfigOrRelation, but with _ instead of -.
        field_names = [f'_{f.replace("-", "_")}' for f in REQUIRED_INGRESS_RELATION_FIELDS]
        return all(getattr(conf_or_rel, f) for f in field_names)

    def _delete_unused_services(self, current_svc_names: List[str]) -> None:
        """Delete services and ingresses that are no longer used.

        Args:
            current_svc_names: service names set by config or relation data.
        """
        api = self._core_v1_api()
        all_services = api.list_namespaced_service(  # type: ignore[attr-defined]
            namespace=self._namespace, label_selector=f"{CREATED_BY_LABEL}={self.app.name}"
        )
        all_svc_names = tuple(item.metadata.name for item in all_services.items)
        unused_svc_names = tuple(
            svc_name
            for svc_name in all_svc_names
            if svc_name.replace("-service", "") not in current_svc_names
        )
        LOGGER.debug(
            "Checking for unused services. Configured: %s Found: %s Unused: %s",
            current_svc_names,
            all_svc_names,
            unused_svc_names,
        )
        for unused_svc_name in unused_svc_names:
            api.delete_namespaced_service(  # type: ignore[attr-defined]
                name=unused_svc_name,
                namespace=self._namespace,
            )
            LOGGER.info(
                "Service deleted in namespace %s with name %s",
                self._namespace,
                unused_svc_name,
            )

    def _define_services(self) -> None:
        """Create or update the services in Kubernetes from multiple ingress relations."""
        for conf_or_rel in self._all_config_or_relations:
            # By default, the service name is "". If there is no value set, we might be missing
            # the needed relation data from that relation at this moment. Skip creating a Service
            # for the current relation; it will be created when the relation data is set.
            if self._has_required_fields(conf_or_rel):
                self._define_service(conf_or_rel)

    def _define_service(self, conf_or_rel: _ConfigOrRelation) -> None:
        """Create or update a service in kubernetes.

        Args:
            conf_or_rel: Ingress configuration or relation class.
        """
        api = self._core_v1_api()
        body = conf_or_rel._get_k8s_service(self.app.name)
        services = api.list_namespaced_service(  # type: ignore[attr-defined]
            namespace=self._namespace
        )
        if conf_or_rel._k8s_service_name in [x.metadata.name for x in services.items]:
            api.patch_namespaced_service(  # type: ignore[attr-defined]
                name=conf_or_rel._k8s_service_name,
                namespace=self._namespace,
                body=body,
            )
            LOGGER.info(
                "Service updated in namespace %s with name %s",
                self._namespace,
                conf_or_rel._service_name,
            )
        else:
            api.create_namespaced_service(  # type: ignore[attr-defined]
                namespace=self._namespace,
                body=body,
            )
            LOGGER.info(
                "Service created in namespace %s with name %s",
                self._namespace,
                conf_or_rel._service_name,
            )

    def _remove_service(self, conf_or_rel: _ConfigOrRelation) -> None:
        """Remove the created service in kubernetes.

        Args:
            conf_or_rel: Ingress configuration or relation class.
        """
        api = self._core_v1_api()
        services = api.list_namespaced_service(  # type: ignore[attr-defined]
            namespace=self._namespace
        )
        if conf_or_rel._k8s_service_name in [x.metadata.name for x in services.items]:
            api.delete_namespaced_service(  # type: ignore[attr-defined]
                name=conf_or_rel._k8s_service_name,
                namespace=self._namespace,
            )
            LOGGER.info(
                "Service deleted in namespace %s with name %s",
                self._namespace,
                conf_or_rel._service_name,
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

    def _delete_unused_ingresses(self, current_svc_hostnames: List[str]) -> None:
        """Delete ingresses that are no longer managed by nginx-ingress-integrator charm.

        Args:
            current_svc_hostnames: service hostnames set by config or relation data
        """
        api = self._networking_v1_api()
        all_ingresses = api.list_namespaced_ingress(  # type: ignore[attr-defined]
            namespace=self._namespace, label_selector=f"{CREATED_BY_LABEL}={self.app.name}"
        )
        all_svc_hostnames = tuple(ingress.spec.rules[0].host for ingress in all_ingresses.items)
        unused_svc_hostnames = tuple(
            hostname for hostname in all_svc_hostnames if hostname not in current_svc_hostnames
        )
        LOGGER.debug(
            "Checking for unused ingresses. Configured: %s Found: %s Unused: %s",
            current_svc_hostnames,
            all_svc_hostnames,
            unused_svc_hostnames,
        )
        for unused_src_hostname in unused_svc_hostnames:
            self._remove_ingress(self._ingress_name(unused_src_hostname))

    def _define_ingresses(self, excluded_relation: Optional[Relation] = None) -> None:
        """(Re)Creates the Ingress Resources in Kubernetes from multiple ingress relations.

        Creates the Kubernetes Ingress Resource if it does not exist, or updates it if it does.
        The Ingress-related data is retrieved from the Charm's configuration and from the ingress
        relations.

        Args:
            excluded_relation: The relation for which Ingress rules should not be created.
                For example, when a relation is broken, Ingress rules for it are no longer
                necessary, hence, it is to be excluded. Additionally, any Ingress objects that it
                required and that are no longer needed by other relations will be deleted.
        """
        config_or_relations = self._all_config_or_relations
        if excluded_relation:
            config_or_relations = filter(
                lambda conf_or_rel: conf_or_rel.relation != excluded_relation,
                config_or_relations,
            )

        # Filter out any cases in which we don't have data set (e.g.: missing relation data)
        config_or_relations = filter(self._has_required_fields, config_or_relations)

        ingresses = [
            conf_or_rel._get_k8s_ingress(self.app.name) for conf_or_rel in config_or_relations
        ]

        ingresses = self._process_ingresses(ingresses)

        for ingress in ingresses:
            self._define_ingress(ingress)

    def _process_ingresses(self, ingresses: List) -> List:
        """Process ingresses, or raise an exception if there are unresolvable conflicts.

        Args:
            ingresses: List of ingresses to process.

        Returns:
            A list of fully processed ingress objects.

        Raises:
            ConflictingAnnotationsError: if there are conflicting annotations.
            ConflictingRoutesError: if there are conflicting routes.
            InvalidHostnameError: if there is an invalid hostname.
            InvalidBackendProtocolError: if an invalid backend protocol is used.
        """
        # If there are Ingress rules for the same service-hostname, we need to squash those
        # rules together. This will be used to group the rules by their host.
        ingress_paths = {}

        # Mapping between a hostname and the first ingress defining that hostname. Its metadata
        # will be used for defining the Kubernetes Ingress Resource for the rules having the
        # same hostname. The metadata used will be from the first rule that references that
        # hostname.
        hostname_ingress = {}
        for ingress in ingresses:
            # A relation could have defined additional-hostnames, so there could be more than
            # one rule. Those hostnames might also be used in other relations.
            if not is_backend_protocol_valid(
                ingress.metadata.annotations["nginx.ingress.kubernetes.io/backend-protocol"]
            ):
                raise InvalidBackendProtocolError()

            for rule in ingress.spec.rules:
                if not invalid_hostname_check(rule.host):
                    raise InvalidHostnameError()

                if rule.host not in ingress_paths:
                    # The same paths array is used for any additional-hostnames given, so we need
                    # to make our own copy.
                    ingress_paths[rule.host] = rule.http.paths.copy()
                    hostname_ingress[rule.host] = ingress
                    continue

                # Ensure that the annotations for this rule match the others in the same group.
                other_metadata = hostname_ingress[rule.host].metadata
                if ingress.metadata.annotations != other_metadata.annotations:
                    LOGGER.error(
                        "Annotations that will be set do not match for the rule:\n"
                        "Rule: %s\nAnnotations: %s\nUsed Annotations: %s",
                        rule,
                        ingress.metadata.annotations,
                        other_metadata.annotations,
                    )
                    raise ConflictingAnnotationsError()

                # Ensure that the exact same route for this route was not yet defined.
                defined_paths = ingress_paths[rule.host]
                for item in rule.http.paths:
                    duplicate_paths = [
                        defined_path
                        for defined_path in defined_paths
                        if defined_path.path == item.path
                    ]
                    if duplicate_paths:
                        LOGGER.error(
                            "Duplicate routes found:\nFirst route: %s\nSecond route: %s",
                            duplicate_paths[0],
                            item,
                        )
                        raise ConflictingRoutesError()

                # Extend the list of routes for this hostname.
                ingress_paths[rule.host].extend(rule.http.paths)

        # Create the new Kubernetes Ingress Objects that are to be added.
        ingress_objs = []
        for hostname, paths in ingress_paths.items():
            # Use the metadata from the first rule.
            initial_ingress = hostname_ingress[hostname]
            add_ingress = self._create_k8s_ingress_obj(
                hostname, initial_ingress, paths, self.app.name
            )
            ingress_objs.append(add_ingress)

        return ingress_objs

    def _ingress_name(self, hostname: str) -> str:
        """Return the Kubernetes Ingress Resource name based on the given hostname.

        Args:
            hostname: The base hostname to build the ingress name for.

        Returns:
            A formatted ingress name.
        """
        ingress_name = _INGRESS_SUB_REGEX.sub("-", hostname)
        return f"{ingress_name}-ingress"

    def _create_k8s_ingress_obj(
        self, svc_hostname: str, initial_ingress: Any, paths: Any, label: str
    ) -> Any:
        """Create a Kubernetes Ingress Resources with the given data.

        Args:
            svc_hostname: Ingress service hostname.
            initial_ingress: Initial ingress previously built.
            paths: Ingress paths.
            label: Ingress label.

        Returns:
            An Ingress object.
        """
        # Create a Ingress Object with the new ingress rules and return it.
        rule = kubernetes.client.V1IngressRule(
            host=svc_hostname,
            http=kubernetes.client.V1HTTPIngressRuleValue(paths=paths),
        )
        # We're going to use an ingress name based on the desired service hostname.
        ingress_name = self._ingress_name(svc_hostname)
        new_spec = kubernetes.client.V1IngressSpec(rules=[rule])

        # The service hostname might be configured to use TLS.
        if initial_ingress.spec.tls:
            new_spec.tls = [
                kubernetes.client.V1IngressTLS(
                    hosts=[svc_hostname],
                    secret_name=initial_ingress.spec.tls[0].secret_name,
                )
            ]
        return kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=ingress_name,
                annotations=initial_ingress.metadata.annotations,
                labels={CREATED_BY_LABEL: label},
            ),
            spec=new_spec,
        )

    def _define_ingress(self, body: Any) -> None:
        """Create or update an ingress in kubernetes.

        Args:
            body: Ingress resource body to configure.
        """
        api = self._networking_v1_api()
        self._look_up_and_set_ingress_class(api, body)
        ingress_name = body.metadata.name
        ingresses = api.list_namespaced_ingress(namespace=self._namespace)
        if ingress_name in [x.metadata.name for x in ingresses.items]:
            api.replace_namespaced_ingress(
                name=ingress_name,
                namespace=self._namespace,
                body=body,
            )
            LOGGER.info(
                "Ingress updated in namespace %s with name %s",
                self._namespace,
                ingress_name,
            )
        else:
            api.create_namespaced_ingress(
                namespace=self._namespace,
                body=body,
            )
            LOGGER.info(
                "Ingress created in namespace %s with name %s",
                self._namespace,
                ingress_name,
            )

    def _remove_ingress(self, ingress_name: str) -> None:
        """Remove ingress resource.

        Args:
            ingress_name: Ingress resource name.
        """
        api = self._networking_v1_api()
        ingresses = api.list_namespaced_ingress(namespace=self._namespace)
        if ingress_name in [x.metadata.name for x in ingresses.items]:
            api.delete_namespaced_ingress(ingress_name, self._namespace)
            LOGGER.info(
                "Ingress deleted in namespace %s with name %s",
                self._namespace,
                ingress_name,
            )

    def _delete_unused_resources(self) -> None:
        """Delete unused services and ingresses."""
        svc_names = [conf_or_rel._service_name for conf_or_rel in self._all_config_or_relations]
        self._delete_unused_services(svc_names)
        svc_hostnames = [
            conf_or_rel._service_hostname for conf_or_rel in self._all_config_or_relations
        ]
        all_additional_hostnames = [
            conf_or_rel._additional_hostnames for conf_or_rel in self._all_config_or_relations
        ]
        for additional_hostname in all_additional_hostnames:
            svc_hostnames.extend(additional_hostname)
        self._delete_unused_ingresses(svc_hostnames)

    def _on_config_changed(self, _: HookEvent) -> None:
        """Handle the config changed event.

        Raises:
            ConflictingAnnotationsError: if there are conflicting annotations.
            ConflictingRoutesError: if there are conflicting routes.
            InvalidHostnameError: if there is an invalid hostname.
            InvalidBackendProtocolError: if an invalid backend protocol is used.
        """
        msg = ""
        # We only want to do anything here if we're the leader to avoid
        # collision if we've scaled out this application.
        svc_names = [conf_or_rel._service_name for conf_or_rel in self._all_config_or_relations]
        if self.unit.is_leader() and any(svc_names):
            try:
                self._define_services()
                self._define_ingresses()
                msgs = []
                self.unit.status = WaitingStatus("Waiting for ingress IP availability")
                ingress_ips = self._report_ingress_ips()
                if ingress_ips:
                    msgs.append(f"Ingress IP(s): {', '.join(ingress_ips)}")
                msgs.append(f"Service IP(s): {', '.join(self._report_service_ips())}")
                msg = ", ".join(msgs)
                self._delete_unused_resources()
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
            except ConflictingAnnotationsError:
                self.unit.status = BlockedStatus(
                    "Conflicting annotations from relations. Run juju debug-log for details. "
                    "Set manually via juju config."
                )
                return
            except ConflictingRoutesError:
                self.unit.status = BlockedStatus(
                    "Duplicate route found; cannot add ingress. Run juju debug-log for details."
                )
                return
            except InvalidHostnameError:
                self.unit.status = BlockedStatus(INVALID_HOSTNAME_MSG)
                return
            except InvalidBackendProtocolError:
                self.unit.status = BlockedStatus(INVALID_BACKEND_PROTOCOL_MSG)
                return
        self.unit.set_workload_version(self._get_kubernetes_library_version())
        self.unit.status = ActiveStatus(msg)

    def _get_kubernetes_library_version(self) -> str:
        """Retrieve the current version of Kubernetes library.

        Returns:
            The Kubernetes library used.
        """
        return kubernetes.__version__

    def _on_ingress_broken(self, event: Any) -> None:
        """Handle the ingress broken event.

        Args:
            event: The event that fires this method.

        Raises:
            An error if there are insufficient permissions to delete an ingress.
            ConflictingAnnotationsError: if there are conflicting annotations.
            ConflictingRoutesError: if there are conflicting routes.
            InvalidHostnameError: if there is an invalid hostname.
            InvalidBackendProtocolError: an invalid backend protocol.
        """
        conf_or_rel = _ConfigOrRelation(self.model, {}, event.relation, self._multiple_relations)
        if self.unit.is_leader() and conf_or_rel._ingress_name:
            try:
                # NOTE: _define_ingresses will recreate the Kubernetes Ingress Resources based
                # on the existing relations, and remove any resources that are no longer needed
                # (they were needed by the event relation).
                self._define_ingresses(excluded_relation=event.relation)
                self._delete_unused_resources()
            except kubernetes.client.exceptions.ApiException as exception:
                if exception.status == 403:
                    LOGGER.error(
                        "Insufficient permissions to delete the k8s ingress resource, "
                        "will request `juju trust` to be run"
                    )
                    juju_trust_cmd = f"juju trust {self.app.name} --scope=cluster"
                    self.unit.status = BlockedStatus(
                        f"Insufficient permissions, try: `{juju_trust_cmd}`"
                    )
                    return
                raise
            except ConflictingAnnotationsError:
                self.unit.status = BlockedStatus(
                    "Conflicting annotations from relations. Run juju debug-log for details. "
                    "Set manually via juju config."
                )
                return
            except ConflictingRoutesError:
                self.unit.status = BlockedStatus(
                    "Duplicate route found; cannot add ingress. Run juju debug-log for details."
                )
                return
            except InvalidHostnameError:
                self.unit.status = BlockedStatus(INVALID_HOSTNAME_MSG)
                return
            except InvalidBackendProtocolError:
                self.unit.status = BlockedStatus(INVALID_BACKEND_PROTOCOL_MSG)
                return
        self.unit.status = ActiveStatus()


if __name__ == "__main__":  # pragma: no cover
    main(NginxIngressCharm)
