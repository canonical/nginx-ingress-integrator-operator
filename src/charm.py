#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import re

import kubernetes.client

from charms.nginx_ingress_integrator.v0.ingress import (
    IngressCharmEvents,
    IngressProvides,
    RELATION_INTERFACES_MAPPINGS,
    RELATION_INTERFACES_MAPPINGS_VALUES,
    REQUIRED_INGRESS_RELATION_FIELDS,
)
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus


LOGGER = logging.getLogger(__name__)
_INGRESS_SUB_REGEX = re.compile("[^0-9a-zA-Z]")
BOOLEAN_CONFIG_FIELDS = ["rewrite-enabled"]


def _core_v1_api():
    """Use the v1 k8s API."""
    return kubernetes.client.CoreV1Api()


def _networking_v1_api():
    """Use the v1 beta1 networking API."""
    return kubernetes.client.NetworkingV1Api()


class ConflictingAnnotationsException(Exception):
    pass


class ConflictingRoutesException(Exception):
    pass


class _ConfigOrRelation(object):
    """Class containing data from the Charm configuration, or from a relation."""

    def __init__(self, model, config, relation, multiple_relations):
        """Creates a _ConfigOrRelation Object.

        :param model: The charm model.
        :param config: The charm's configuration.
        :param relation: One of the charm's relations, if any.
        :param multiple_relations: If the charm has more than one relation.
        """
        super().__init__()
        self.model = model
        self.config = config
        self.relation = relation
        self.multiple_relations = multiple_relations

    def _get_config(self, field):
        """Helper method to get data from config."""
        # Config fields with a default of None don't appear in the dict
        config_data = self.config.get(field, None)
        # A value of False is valid in these fields, so check it's not a null-value instead
        if field in BOOLEAN_CONFIG_FIELDS and (
            config_data is not None and config_data != ""
        ):
            return config_data
        if config_data:
            return config_data

        return None

    def _get_relation(self, field):
        """Helper method to get data from the relation, if any."""
        if self.relation:
            try:
                # We want to prioritise relation-interfaces data if we have it.
                if field in RELATION_INTERFACES_MAPPINGS_VALUES:
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

    def _get_config_or_relation_data(self, field, fallback):
        """Helper method to get data from config or the ingress relation, in that order."""
        data = self._get_config(field)
        if data is not None:
            return data

        data = self._get_relation(field)
        if data is not None:
            return data

        return fallback

    def _get_relation_data_or_config(self, field, fallback):
        """Helper method to get data from the ingress relation or config, in that order."""
        data = self._get_relation(field)
        if data is not None:
            return data

        data = self._get_config(field)
        if data is not None:
            return data

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
        # If there are 2 or more services configured to use the same service-hostname, the
        # controller nginx/nginx-ingress requires them to be in the same Kubernetes Ingress object.
        # Otherwise, Ingress will be served for only one of the services.
        # Because of this, we'll have to group all ingresses into the same Kubernetes Resource
        # based on their requested service-hostname.
        svc_hostname = self._get_config_or_relation_data("service-hostname", "")
        ingress_name = _INGRESS_SUB_REGEX.sub("-", svc_hostname)
        return "{}-ingress".format(ingress_name)

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
    def _owasp_modsecurity_crs(self):
        """Return a boolean indicating whether OWASP ModSecurity CRS is enabled."""
        return self._get_config_or_relation_data("owasp-modsecurity-crs", False)

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
        return " ".join(
            [x.strip() for x in retry.split(",") if x.strip() in accepted_values]
        )

    @property
    def _service_hostname(self):
        """Return the hostname for the service we're connecting to."""
        return self._get_config_or_relation_data("service-hostname", "")

    @property
    def _service_name(self):
        """Return the name of the service we're connecting to."""
        # NOTE: If the charm has multiple relations, use the service name given by the relation
        # in order to avoid service name conflicts.
        if self.multiple_relations:
            return self._get_relation_data_or_config("service-name", "")
        return self._get_config_or_relation_data("service-name", "")

    @property
    def _service_port(self):
        """Return the port for the service we're connecting to."""
        # NOTE: If the charm has multiple relations, use the service port given by the relation.
        if self.multiple_relations:
            return int(self._get_relation_data_or_config("service-port", 0))
        return int(self._get_relation_data_or_config("service-port", 0))

    @property
    def _path_routes(self):
        """Return the path routes to use for the k8s ingress."""
        # NOTE: If the charm has multiple relations, use the path routes given by the relation
        # in order to avoid same route conflicts.
        if self.multiple_relations:
            return self._get_relation_data_or_config("path-routes", "/").split(",")
        return self._get_config_or_relation_data("path-routes", "/").split(",")

    @property
    def _session_cookie_max_age(self):
        """Return the session-cookie-max-age to use for k8s ingress."""
        session_cookie_max_age = self._get_config_or_relation_data(
            "session-cookie-max-age", 0
        )
        if session_cookie_max_age:
            return str(session_cookie_max_age)
        # Don't return "0" which would evaluate to True.
        return ""

    @property
    def _tls_secret_name(self):
        """Return the tls-secret-name to use for k8s ingress (if any)."""
        return self._get_config_or_relation_data("tls-secret-name", "")

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
        hostnames.extend(
            [
                x
                for x in self._get_config_or_relation_data(
                    "additional-hostnames", ""
                ).split(",")
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

        annotations = {
            "nginx.ingress.kubernetes.io/proxy-body-size": self._max_body_size
        }
        if self._limit_rps:
            annotations["nginx.ingress.kubernetes.io/limit-rps"] = self._limit_rps
            if self._limit_whitelist:
                annotations[
                    "nginx.ingress.kubernetes.io/limit-whitelist"
                ] = self._limit_whitelist
        if self._owasp_modsecurity_crs:
            annotations["nginx.ingress.kubernetes.io/enable-modsecurity"] = "true"
            annotations[
                "nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"
            ] = "true"
            annotations[
                "nginx.ingress.kubernetes.io/modsecurity-snippet"
            ] = "SecRuleEngine On\nInclude /etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf"
        if self._retry_errors:
            annotations[
                "nginx.ingress.kubernetes.io/proxy-next-upstream"
            ] = self._retry_errors
        if self._rewrite_enabled:
            annotations[
                "nginx.ingress.kubernetes.io/rewrite-target"
            ] = self._rewrite_target
        if self._session_cookie_max_age:
            annotations["nginx.ingress.kubernetes.io/affinity"] = "cookie"
            annotations["nginx.ingress.kubernetes.io/affinity-mode"] = "balanced"
            annotations[
                "nginx.ingress.kubernetes.io/session-cookie-change-on-failure"
            ] = "true"
            annotations[
                "nginx.ingress.kubernetes.io/session-cookie-max-age"
            ] = self._session_cookie_max_age
            annotations[
                "nginx.ingress.kubernetes.io/session-cookie-name"
            ] = "{}_AFFINITY".format(self._service_name.upper())
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


class NginxIngressCharm(CharmBase):
    """Charm the service."""

    _authed = False
    on = IngressCharmEvents()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.describe_ingresses_action, self._describe_ingresses_action
        )

        # 'ingress' relation handling.
        self.ingress = IngressProvides(self)
        # When the 'ingress' is ready to configure, do so.
        self.framework.observe(self.on.ingress_available, self._on_config_changed)
        self.framework.observe(self.on.ingress_broken, self._on_ingress_broken)

    @property
    def _all_config_or_relations(self):
        """Get all configuration and relation data."""
        all_relations = self.model.relations["ingress"] or [None]
        multiple_rels = self._multiple_relations
        return [
            _ConfigOrRelation(self.model, self.config, relation, multiple_rels)
            for relation in all_relations
        ]

    @property
    def _multiple_relations(self):
        """Return a boolean indicating if we're related to multiple applications."""
        return len(self.model.relations["ingress"]) > 1

    @property
    def _namespace(self):
        """Namespace for this ingress."""
        # We're querying the first one here because this will always be the same
        # for all instances. It would be very unusual for a relation to specify
        # this (arguably we should remove this as a relation option), so if set
        # via config it will be the same for all relations.
        return self._all_config_or_relations[0]._namespace

    def _describe_ingresses_action(self, event):
        """Handle the 'describe-ingresses' action."""
        self.k8s_auth()
        api = _networking_v1_api()

        ingresses = api.list_namespaced_ingress(namespace=self._namespace)
        event.set_results({"ingresses": ingresses})

    def k8s_auth(self):
        """Authenticate to kubernetes."""
        if self._authed:
            return

        kubernetes.config.load_incluster_config()

        self._authed = True

    def _report_service_ips(self):
        """Report on service IP(s)."""
        self.k8s_auth()
        api = _core_v1_api()
        services = api.list_namespaced_service(namespace=self._namespace)
        all_k8s_service_names = [
            rel._k8s_service_name for rel in self._all_config_or_relations
        ]
        return [
            x.spec.cluster_ip
            for x in services.items
            if x.metadata.name in all_k8s_service_names
        ]

    def _has_required_fields(self, conf_or_rel: _ConfigOrRelation):
        """Checks if the given config or relation has the required fields set."""
        # We use the same names in _ConfigOrRelation, but with _ instead of -.
        field_names = [
            "_%s" % f.replace("-", "_") for f in REQUIRED_INGRESS_RELATION_FIELDS
        ]
        return all([getattr(conf_or_rel, f) for f in field_names])

    def _define_services(self):
        """Create or update the services in Kubernetes from multiple ingress relations."""
        for conf_or_rel in self._all_config_or_relations:
            # By default, the service name is "". If there is no value set, we might be missing
            # the needed relation data from that relation at this moment. Skip creating a Service
            # for the current relation; it will be created when the relation data is set.
            if self._has_required_fields(conf_or_rel):
                self._define_service(conf_or_rel)

    def _define_service(self, conf_or_rel: _ConfigOrRelation):
        """Create or update a service in kubernetes."""
        self.k8s_auth()
        api = _core_v1_api()
        body = conf_or_rel._get_k8s_service()
        services = api.list_namespaced_service(namespace=self._namespace)
        if conf_or_rel._k8s_service_name in [x.metadata.name for x in services.items]:
            api.patch_namespaced_service(
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
            api.create_namespaced_service(
                namespace=self._namespace,
                body=body,
            )
            LOGGER.info(
                "Service created in namespace %s with name %s",
                self._namespace,
                conf_or_rel._service_name,
            )

    def _remove_service(self, conf_or_rel: _ConfigOrRelation):
        """Remove the created service in kubernetes."""
        self.k8s_auth()
        api = _core_v1_api()
        services = api.list_namespaced_service(namespace=self._namespace)
        if conf_or_rel._k8s_service_name in [x.metadata.name for x in services.items]:
            api.delete_namespaced_service(
                name=conf_or_rel._k8s_service_name,
                namespace=self._namespace,
            )
            LOGGER.info(
                "Service deleted in namespace %s with name %s",
                self._namespace,
                conf_or_rel._service_name,
            )

    def _look_up_and_set_ingress_class(self, api, body):
        """Set the configured ingress class, otherwise the cluster's default ingress class."""
        ingress_class = self.config["ingress-class"]
        if not ingress_class:
            defaults = [
                item.metadata.name
                for item in api.list_ingress_class().items
                if item.metadata.annotations.get(
                    "ingressclass.kubernetes.io/is-default-class"
                )
                == "true"
            ]

            if not defaults:
                LOGGER.warning("Cluster has no default ingress class defined")
                return

            if len(defaults) > 1:
                LOGGER.warning(
                    "Multiple default ingress classes defined, declining to choose between them. "
                    "They are: {}".format(" ".join(sorted(defaults)))
                )
                return

            ingress_class = defaults[0]
            LOGGER.info(
                "Using ingress class {} as it is the cluster's default".format(
                    ingress_class
                )
            )

        body.spec.ingress_class_name = ingress_class

    def _define_ingresses(self, excluded_relation=None):
        """(Re)Creates the Ingress Resources in Kubernetes from multiple ingress relations.

        Creates the Kubernetes Ingress Resource if it does not exist, or updates it if it does.
        The Ingress-related data is retrieved from the Charm's configuration and from the ingress
        relations.

        :param excluded_relation: The relation for which Ingress rules should not be created.
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
            conf_or_rel._get_k8s_ingress() for conf_or_rel in config_or_relations
        ]

        ingresses = self._process_ingresses(ingresses)

        # Check if we need to remove any Ingresses from the excluded relation. If it has hostnames
        # that are not used by any other relation, we need to remove them.
        if excluded_relation:
            conf_or_rel = _ConfigOrRelation(
                self.model, self.config, excluded_relation, self._multiple_relations
            )
            excluded_ingress = conf_or_rel._get_k8s_ingress()

            # The Kubernetes Ingress Resources we're creating only has 1 rule per hostname.
            used_hostnames = [ingress.spec.rules[0].host for ingress in ingresses]
            for rule in excluded_ingress.spec.rules:
                if rule.host not in used_hostnames:
                    self._remove_ingress(self._ingress_name(rule.host))

        for ingress in ingresses:
            self._define_ingress(ingress)

    def _process_ingresses(self, ingresses):
        """Process ingresses, or raise an exception if there are unresolvable conflicts."""
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
            for rule in ingress.spec.rules:
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
                    raise ConflictingAnnotationsException()

                # Ensure that the exact same route for this route was not yet defined.
                defined_paths = ingress_paths[rule.host]
                for path in rule.http.paths:
                    duplicate_paths = list(
                        filter(lambda p: p.path == path.path, defined_paths)
                    )
                    if duplicate_paths:
                        LOGGER.error(
                            "Duplicate routes found:\nFirst route: %s\nSecond route: %s",
                            duplicate_paths[0],
                            path,
                        )
                        raise ConflictingRoutesException()

                # Extend the list of routes for this hostname.
                ingress_paths[rule.host].extend(rule.http.paths)

        # Create the new Kubernetes Ingress Objects that are to be added.
        ingress_objs = []
        for hostname, paths in ingress_paths.items():
            # Use the metadata from the first rule.
            initial_ingress = hostname_ingress[hostname]
            add_ingress = self._create_k8s_ingress_obj(hostname, initial_ingress, paths)
            ingress_objs.append(add_ingress)

        return ingress_objs

    def _ingress_name(self, hostname):
        """Returns the Kubernetes Ingress Resource name based on the given hostname."""
        ingress_name = _INGRESS_SUB_REGEX.sub("-", hostname)
        return "{}-ingress".format(ingress_name)

    def _create_k8s_ingress_obj(self, svc_hostname, initial_ingress, paths):
        """Creates a Kubernetes Ingress Resources with the given data."""

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
            ),
            spec=new_spec,
        )

    def _define_ingress(self, body):
        """Create or update an ingress in kubernetes."""
        self.k8s_auth()
        api = _networking_v1_api()
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

    def _remove_ingress(self, ingress_name):
        """Remove ingress resource."""
        self.k8s_auth()
        api = _networking_v1_api()
        ingresses = api.list_namespaced_ingress(namespace=self._namespace)
        if ingress_name in [x.metadata.name for x in ingresses.items]:
            api.delete_namespaced_ingress(ingress_name, self._namespace)
            LOGGER.info(
                "Ingress deleted in namespace %s with name %s",
                self._namespace,
                ingress_name,
            )

    def _on_config_changed(self, _):
        """Handle the config changed event."""
        msg = ""
        # We only want to do anything here if we're the leader to avoid
        # collision if we've scaled out this application.
        svc_names = [
            conf_or_rel._service_name for conf_or_rel in self._all_config_or_relations
        ]
        print(svc_names)
        if self.unit.is_leader() and any(svc_names):
            try:
                self._define_services()
                self._define_ingresses()

                # It's not recommended to do this via ActiveStatus, but we don't
                # have another way of reporting status yet.
                msg = "Ingress with service IP(s): {}".format(
                    ", ".join(self._report_service_ips())
                )
            except kubernetes.client.exceptions.ApiException as e:
                if e.status == 403:
                    LOGGER.error(
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
            except ConflictingAnnotationsException:
                self.unit.status = BlockedStatus(
                    "Conflicting annotations from relations. Run juju debug-log for details. "
                    "Set manually via juju config."
                )
                return
            except ConflictingRoutesException:
                self.unit.status = BlockedStatus(
                    "Duplicate route found; cannot add ingress. Run juju debug-log for details."
                )
                return
        self.unit.status = ActiveStatus(msg)

    def _on_ingress_broken(self, event):
        """Handle the ingress broken event."""
        conf_or_rel = _ConfigOrRelation(
            self.model, {}, event.relation, self._multiple_relations
        )
        if self.unit.is_leader() and conf_or_rel._ingress_name:
            try:
                # NOTE: _define_ingresses will recreate the Kubernetes Ingress Resources based
                # on the existing relations, and remove any resources that are no longer needed
                # (they were needed by the event relation).
                self._define_ingresses(excluded_relation=event.relation)
                self._remove_service(conf_or_rel)
            except kubernetes.client.exceptions.ApiException as e:
                if e.status == 403:
                    LOGGER.error(
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
            except ConflictingAnnotationsException:
                self.unit.status = BlockedStatus(
                    "Conflicting annotations from relations. Run juju debug-log for details. "
                    "Set manually via juju config."
                )
                return
            except ConflictingRoutesException:
                self.unit.status = BlockedStatus(
                    "Duplicate route found; cannot add ingress. Run juju debug-log for details."
                )
                return

        self.unit.status = ActiveStatus()


if __name__ == "__main__":  # pragma: no cover
    main(NginxIngressCharm)
