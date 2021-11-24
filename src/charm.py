#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import kubernetes.client

from charms.nginx_ingress_integrator.v0.ingress import (
    IngressCharmEvents,
    IngressProvides,
)
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus


logger = logging.getLogger(__name__)

BOOLEAN_CONFIG_FIELDS = ["rewrite-enabled"]


def _core_v1_api():
    """Use the v1 k8s API."""
    return kubernetes.client.CoreV1Api()


def _networking_v1_api():
    """Use the v1 beta1 networking API."""
    return kubernetes.client.NetworkingV1Api()


class NginxIngressCharm(CharmBase):
    """Charm the service."""

    _authed = False
    on = IngressCharmEvents()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.describe_ingresses_action, self._describe_ingresses_action)

        # 'ingress' relation handling.
        self.ingress = IngressProvides(self)
        # When the 'ingress' is ready to configure, do so.
        self.framework.observe(self.on.ingress_available, self._on_config_changed)
        self.framework.observe(self.on.ingress_broken, self._on_ingress_broken)

    def _describe_ingresses_action(self, event):
        """Handle the 'describe-ingresses' action."""
        self.k8s_auth()
        api = _networking_v1_api()
        ingresses = api.list_namespaced_ingress(namespace=self._namespace)
        event.set_results({"ingresses": ingresses})

    def _get_config_or_relation_data(self, field, fallback):
        """Helper method to get data from config or the ingress relation."""
        # Config fields with a default of None don't appear in the dict
        config_data = self.config.get(field, None)
        # A value of False is valid in these fields, so check it's not a null-value instead
        if field in BOOLEAN_CONFIG_FIELDS and (config_data is not None and config_data != ""):
            return config_data
        if config_data:
            return config_data
        relation = self.model.get_relation("ingress")
        if relation:
            try:
                return relation.data[relation.app][field]
            except KeyError:
                # Our relation isn't passing the information we're querying.
                return fallback
        return fallback

    @property
    def _k8s_service_name(self):
        """Return a service name for the use creating a k8s service."""
        # Avoid collision with service name created by Juju. Currently
        # Juju creates a K8s service listening on port 65535/TCP so we
        # need to create a separate one.
        return "{}-service".format(self._service_name)

    @property
    def _ingress_name(self):
        """Return an ingress name for use creating a k8s ingress."""
        # Follow the same naming convention as Juju.
        return "{}-ingress".format(self._get_config_or_relation_data("service-name", ""))

    @property
    def _limit_rps(self):
        """Return limit-rps value from config or relation."""
        limit_rps = self._get_config_or_relation_data("limit-rps", 0)
        if limit_rps:
            return str(limit_rps)
        # Don't return "0" which would evaluate to True.
        return ""

    @property
    def _limit_whitelist(self):
        """Return the limit-whitelist value from config or relation."""
        return self._get_config_or_relation_data("limit-whitelist", "")

    @property
    def _max_body_size(self):
        """Return the max-body-size to use for k8s ingress."""
        max_body_size = self._get_config_or_relation_data("max-body-size", 0)
        return "{}m".format(max_body_size)

    @property
    def _rewrite_enabled(self):
        """Return whether rewriting should be enabled from config or relation"""
        value = self._get_config_or_relation_data("rewrite-enabled", True)
        # config data is typed, relation data is a string
        # Convert to string, then compare to a known value.
        return str(value).lower() == "true"

    @property
    def _rewrite_target(self):
        """Return the rewrite target from config or relation."""
        return self._get_config_or_relation_data("rewrite-target", "/")

    @property
    def _namespace(self):
        """Return the namespace to operate on."""
        return self._get_config_or_relation_data("service-namespace", self.model.name)

    @property
    def _retry_errors(self):
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
    def _service_hostname(self):
        """Return the hostname for the service we're connecting to."""
        return self._get_config_or_relation_data("service-hostname", "")

    @property
    def _service_name(self):
        """Return the name of the service we're connecting to."""
        return self._get_config_or_relation_data("service-name", "")

    @property
    def _service_port(self):
        """Return the port for the service we're connecting to."""
        return int(self._get_config_or_relation_data("service-port", 0))

    @property
    def _session_cookie_max_age(self):
        """Return the session-cookie-max-age to use for k8s ingress."""
        session_cookie_max_age = self._get_config_or_relation_data("session-cookie-max-age", 0)
        if session_cookie_max_age:
            return str(session_cookie_max_age)
        # Don't return "0" which would evaluate to True.
        return ""

    @property
    def _tls_secret_name(self):
        """Return the tls-secret-name to use for k8s ingress (if any)."""
        return self._get_config_or_relation_data("tls-secret-name", "")

    def k8s_auth(self):
        """Authenticate to kubernetes."""
        if self._authed:
            return

        kubernetes.config.load_incluster_config()

        self._authed = True

    def _get_k8s_service(self):
        """Get a K8s service definition."""
        return kubernetes.client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=kubernetes.client.V1ObjectMeta(name=self._k8s_service_name),
            spec=kubernetes.client.V1ServiceSpec(
                selector={"app.kubernetes.io/name": self._service_name},
                ports=[
                    kubernetes.client.V1ServicePort(
                        name="tcp-{}".format(self._service_port),
                        port=self._service_port,
                        target_port=self._service_port,
                    )
                ],
            ),
        )

    def _get_k8s_ingress(self):
        """Get a K8s ingress definition."""
        paths = self._get_config_or_relation_data("path-routes", "/").split(",")
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
            for path in paths
        ]

        hostnames = [self._service_hostname]
        hostnames.extend(
            [
                x
                for x in self._get_config_or_relation_data("additional-hostnames", "").split(",")
                if x
            ]
        )
        ingress_rules = [
            kubernetes.client.V1IngressRule(
                host=hostname,
                http=kubernetes.client.V1HTTPIngressRuleValue(paths=ingress_paths),
            )
            for hostname in hostnames
        ]
        spec = kubernetes.client.V1IngressSpec(rules=ingress_rules)

        annotations = {"nginx.ingress.kubernetes.io/proxy-body-size": self._max_body_size}
        if self._rewrite_enabled:
            annotations["nginx.ingress.kubernetes.io/rewrite-target"] = self._rewrite_target
        if self._limit_rps:
            annotations["nginx.ingress.kubernetes.io/limit-rps"] = self._limit_rps
            if self._limit_whitelist:
                annotations["nginx.ingress.kubernetes.io/limit-whitelist"] = self._limit_whitelist
        if self._retry_errors:
            annotations["nginx.ingress.kubernetes.io/proxy-next-upstream"] = self._retry_errors
        if self._session_cookie_max_age:
            annotations["nginx.ingress.kubernetes.io/affinity"] = "cookie"
            annotations["nginx.ingress.kubernetes.io/affinity-mode"] = "balanced"
            annotations["nginx.ingress.kubernetes.io/session-cookie-change-on-failure"] = "true"
            annotations[
                "nginx.ingress.kubernetes.io/session-cookie-max-age"
            ] = self._session_cookie_max_age
            annotations["nginx.ingress.kubernetes.io/session-cookie-name"] = "{}_AFFINITY".format(
                self._service_name.upper()
            )
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

        return kubernetes.client.V1Ingress(
            api_version="networking.k8s.io/v1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=self._ingress_name,
                annotations=annotations,
            ),
            spec=spec,
        )

    def _report_service_ips(self):
        """Report on service IP(s)."""
        self.k8s_auth()
        api = _core_v1_api()
        services = api.list_namespaced_service(namespace=self._namespace)
        return [
            x.spec.cluster_ip for x in services.items if x.metadata.name == self._k8s_service_name
        ]

    def _define_service(self):
        """Create or update a service in kubernetes."""
        self.k8s_auth()
        api = _core_v1_api()
        body = self._get_k8s_service()
        services = api.list_namespaced_service(namespace=self._namespace)
        if self._k8s_service_name in [x.metadata.name for x in services.items]:
            api.patch_namespaced_service(
                name=self._k8s_service_name,
                namespace=self._namespace,
                body=body,
            )
            logger.info(
                "Service updated in namespace %s with name %s",
                self._namespace,
                self._service_name,
            )
        else:
            api.create_namespaced_service(
                namespace=self._namespace,
                body=body,
            )
            logger.info(
                "Service created in namespace %s with name %s",
                self._namespace,
                self._service_name,
            )

    def _remove_service(self):
        """Remove the created service in kubernetes."""
        self.k8s_auth()
        api = _core_v1_api()
        services = api.list_namespaced_service(namespace=self._namespace)
        if self._k8s_service_name in [x.metadata.name for x in services.items]:
            api.delete_namespaced_service(
                name=self._k8s_service_name,
                namespace=self._namespace,
            )
            logger.info(
                "Service deleted in namespace %s with name %s",
                self._namespace,
                self._service_name,
            )

    def _look_up_and_set_ingress_class(self, api, body):
        """Set the configured ingress class, otherwise the cluster's default ingress class."""
        ingress_class = self.config['ingress-class']
        if not ingress_class:
            defaults = [
                item.metadata.name
                for item in api.list_ingress_class().items
                if item.metadata.annotations.get('ingressclass.kubernetes.io/is-default-class')
                == 'true'
            ]

            if not defaults:
                logger.warning("Cluster has no default ingress class defined")
                return

            if len(defaults) > 1:
                logger.warning(
                    "Multiple default ingress classes defined, declining to choose between them. "
                    "They are: {}".format(' '.join(sorted(defaults)))
                )
                return

            ingress_class = defaults[0]
            logger.info(
                "Using ingress class {} as it is the cluster's default".format(ingress_class)
            )

        body.spec.ingress_class_name = ingress_class

    def _define_ingress(self):
        """Create or update an ingress in kubernetes."""
        self.k8s_auth()
        api = _networking_v1_api()
        body = self._get_k8s_ingress()
        self._look_up_and_set_ingress_class(api, body)
        ingresses = api.list_namespaced_ingress(namespace=self._namespace)
        if self._ingress_name in [x.metadata.name for x in ingresses.items]:
            api.replace_namespaced_ingress(
                name=self._ingress_name,
                namespace=self._namespace,
                body=body,
            )
            logger.info(
                "Ingress updated in namespace %s with name %s",
                self._namespace,
                self._ingress_name,
            )
        else:
            api.create_namespaced_ingress(
                namespace=self._namespace,
                body=body,
            )
            logger.info(
                "Ingress created in namespace %s with name %s",
                self._namespace,
                self._ingress_name,
            )

    def _remove_ingress(self):
        """Remove ingress resource."""
        self.k8s_auth()
        api = _networking_v1_api()
        ingresses = api.list_namespaced_ingress(namespace=self._namespace)
        if self._ingress_name in [x.metadata.name for x in ingresses.items]:
            api.delete_namespaced_ingress(self._ingress_name, self._namespace)
            logger.info(
                "Ingress deleted in namespace %s with name %s",
                self._namespace,
                self._ingress_name,
            )

    def _on_config_changed(self, _):
        """Handle the config changed event."""
        msg = ""
        # We only want to do anything here if we're the leader to avoid
        # collision if we've scaled out this application.
        if self.unit.is_leader() and self._service_name:
            try:
                self._define_service()
                self._define_ingress()
                # It's not recommended to do this via ActiveStatus, but we don't
                # have another way of reporting status yet.
                msg = "Ingress with service IP(s): {}".format(
                    ", ".join(self._report_service_ips())
                )
            except kubernetes.client.exceptions.ApiException as e:
                if e.status == 403:
                    logger.error(
                        "Insufficient permissions to create the k8s service, "
                        "will request `juju trust` to be run"
                    )
                    self.unit.status = BlockedStatus(
                        "Insufficient permissions, try: `juju trust {} --scope=cluster`".format(
                            self.app.name
                        )
                    )
                    return
                else:
                    raise
        self.unit.status = ActiveStatus(msg)

    def _on_ingress_broken(self, _):
        """Handle the ingress broken event."""
        if self.unit.is_leader() and self._ingress_name:
            try:
                self._remove_ingress()
                self._remove_service()
            except kubernetes.client.exceptions.ApiException as e:
                if e.status == 403:
                    logger.error(
                        "Insufficient permissions to delete the k8s ingress resource, "
                        "will request `juju trust` to be run"
                    )
                    self.unit.status = BlockedStatus(
                        "Insufficient permissions, try: `juju trust {} --scope=cluster`".format(
                            self.app.name
                        )
                    )
                    return
                else:
                    raise
        self.unit.status = ActiveStatus()

if __name__ == "__main__":  # pragma: no cover
    main(NginxIngressCharm)
