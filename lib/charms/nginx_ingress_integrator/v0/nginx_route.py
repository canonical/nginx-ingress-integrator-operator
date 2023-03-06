# Copyright 2023 Canonical Ltd.
# Licensed under the Apache2.0, see LICENCE file in charm source for details.
"""Library for the nginx-route relation.

This library contains the Requirer and Provider classes for handling
the nginx-route interface.

Import `NginxRouteRequirer` in your charm, with two required options:
- "self" (the charm itself)
- config

`config` accepts the following keys:
- additional-hostnames
- limit-rps
- limit-whitelist
- max-body-size
- owasp-modsecurity-crs
- owasp-modsecurity-custom-rules
- path-routes
- retry-errors
- rewrite-enabled
- rewrite-target
- service-hostname (required)
- service-name (required)
- service-namespace
- service-port (required)
- session-cookie-max-age
- tls-secret-name

See [the config section](https://charmhub.io/nginx-ingress-integrator/configure) for descriptions
of each, along with the required type.

As an example, add the following to `src/charm.py`:
```python
from charms.nginx_ingress_integrator.v0.nginx_route import NginxRouteRequirer

# In your charm's `__init__` method.
require_nginx_route(
    charm=self,
    service_hostname=self.config["external_hostname"],
    service_name=self.app.name,
    service_port=80
)

```
And then add the following to `metadata.yaml`:
```
requires:
  nginx-route:
    interface: nginx-route
```
You _must_ register the NginxRouteRequirer class as part of the `__init__` method
rather than, for instance, a config-changed event handler, for the relation
changed event to be properly handled.
"""
import logging
import typing
import weakref

from ops.charm import CharmBase, CharmEvents, RelationBrokenEvent, RelationChangedEvent
from ops.framework import EventBase, EventSource, Object
from ops.model import BlockedStatus

# The unique Charmhub library identifier, never change it
LIBID = "c13d5d639bcd09f8c4f5b195264ed53d"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 0

__all__ = ["require_nginx_route", "provide_nginx_route"]

logger = logging.getLogger(__name__)

NGINX_ROUTE_RELATION_FIELDS = [
    {"name": "service-hostname", "type": str, "optional": False},
    {"name": "service-name", "type": str, "optional": False},
    {"name": "service-port", "type": int, "optional": False},
    {"name": "additional-hostnames", "type": str, "optional": True},
    {"name": "limit-rps", "type": int, "optional": True},
    {"name": "limit-whitelist", "type": str, "optional": True},
    {"name": "max-body-size", "type": int, "optional": True},
    {"name": "owasp-modsecurity-crs", "type": str, "optional": True},
    {"name": "owasp-modsecurity-custom-rules", "type": str, "optional": True},
    {"name": "path-routes", "type": str, "optional": True},
    {"name": "retry-errors", "type": str, "optional": True},
    {"name": "rewrite-target", "type": str, "optional": True},
    {"name": "rewrite-enabled", "type": bool, "optional": True},
    {"name": "service-namespace", "type": str, "optional": True},
    {"name": "session-cookie-max-age", "type": int, "optional": True},
    {"name": "tls-secret-name", "type": str, "optional": True},
]


class NginxRouteAvailableEvent(EventBase):
    """NginxRouteAvailableEvent custom event.

    This event indicates the nginx-route provider is available.
    """


class NginxRouteBrokenEvent(RelationBrokenEvent):
    """NginxRouteBrokenEvent custom event.

    This event indicates the nginx-route provider is broken.
    """


class NginxRouteCharmEvents(CharmEvents):
    """Custom charm events.

    Attrs:
        nginx_route_available: Event to indicate that Nginx route relation is available.
        nginx_route_broken: Event to indicate that Nginx route relation is broken.
    """

    nginx_route_available = EventSource(NginxRouteAvailableEvent)
    nginx_route_broken = EventSource(NginxRouteBrokenEvent)


class _NginxRouteRequirer(Object):
    """This class defines the functionality for the 'requires' side of the 'nginx-route' relation.

    Hook events observed:
        - relation-changed
    """

    def __init__(
        self,
        charm: CharmBase,
        config: typing.Dict[str, typing.Union[str, int, bool]],
        nginx_route_relation_name: str = "nginx-route",
    ):
        """Init function for the NginxRouteRequires class.

        Args:
            charm: The charm that requires the nginx-route relation.
            config: Contains all the configuration options for nginx-route.
            nginx_route_relation_name: Specifies the relation name of the relation handled by this
                requirer class. The relation must have the nginx-route interface.
        """
        super().__init__(charm, nginx_route_relation_name)
        self._charm: CharmBase = charm
        self._nginx_route_relation_name = nginx_route_relation_name
        self._charm.framework.observe(
            self._charm.on[self._nginx_route_relation_name].relation_changed,
            self._config_reconciliation,
        )
        # Set default values.
        self._config = {"service-namespace": self._charm.model.name}
        self._config.update(config)
        self._config_reconciliation(None)

    def _config_reconciliation(self, _event=None):
        """Update the nginx-route relation data to be exactly as defined by config."""
        if not self._charm.model.unit.is_leader():
            return
        for relation in self._charm.model.relations[self._nginx_route_relation_name]:
            relation_app_data = relation.data[self._charm.app]
            delete_keys = set(r for r in relation_app_data if r not in self._config)
            for delete_key in delete_keys:
                del relation_app_data[delete_key]
            for relation_field, relation_data_value in self._config.items():
                relation_app_data[relation_field] = str(relation_data_value)


def require_nginx_route(
    *,
    charm: CharmBase,
    service_hostname: str,
    service_name: str,
    service_port: int,
    additional_hostnames: typing.Optional[str] = None,
    limit_rps: typing.Optional[int] = None,
    limit_whitelist: typing.Optional[str] = None,
    max_body_size: typing.Optional[int] = None,
    owasp_modsecurity_crs: typing.Optional[str] = None,
    owasp_modsecurity_custom_rules: typing.Optional[str] = None,
    path_routes: typing.Optional[str] = None,
    retry_errors: typing.Optional[str] = None,
    rewrite_target: typing.Optional[str] = None,
    rewrite_enabled: typing.Optional[bool] = None,
    service_namespace: typing.Optional[str] = None,
    session_cookie_max_age: typing.Optional[int] = None,
    tls_secret_name: typing.Optional[str] = None,
    nginx_route_relation_name: str = "nginx-route",
):
    """Set up nginx-route relation handlers on the requirer side.

    This function must be invoked in the charm class constructor.

    Args:
        charm: The charm that requires the nginx-route relation.
        service_hostname: configure Nginx ingress integrator
            service-hostname option via relation.
        service_name: configure Nginx ingress integrator service-name
            option via relation.
        service_port: configure Nginx ingress integrator service-port
            option via relation.
        additional_hostnames: configure Nginx ingress integrator
            additional-hostnames option via relation, optional.
        limit_rps: configure Nginx ingress integrator limit-rps
            option via relation, optional.
        limit_whitelist: configure Nginx ingress integrator
            limit-whitelist option via relation, optional.
        max_body_size: configure Nginx ingress integrator
            max-body-size option via relation, optional.
        owasp_modsecurity_crs: configure Nginx ingress integrator
            owasp-modsecurity-crs  option via relation, optional.
        owasp_modsecurity_custom_rules: configure Nginx ingress
            integrator owasp-modsecurity-custom-rules option via
            relation, optional.
        path_routes: configure Nginx ingress integrator path-routes
            option via relation, optional.
        retry_errors: configure Nginx ingress integrator retry-errors
            option via relation, optional.
        rewrite_target: configure Nginx ingress integrator
            rewrite-target option via relation, optional.
        rewrite_enabled: configure Nginx ingress integrator
            rewrite-enabled option via relation, optional.
        service_namespace: configure Nginx ingress integrator
            service-namespace option via relation, optional.
        session_cookie_max_age: configure Nginx ingress integrator
            session-cookie-max-age option via relation, optional.
        tls_secret_name: configure Nginx ingress integrator
            tls-secret-name option via relation, optional.
        nginx_route_relation_name: Specifies the relation name of
            the relation handled by this requirer class. The relation
            must have the nginx-route interface.
    """
    config = {}
    if service_hostname is not None:
        config["service-hostname"] = service_hostname
    if service_name is not None:
        config["service-name"] = service_name
    if service_port is not None:
        config["service-port"] = service_port
    if additional_hostnames is not None:
        config["additional-hostnames"] = additional_hostnames
    if limit_rps is not None:
        config["limit-rps"] = limit_rps
    if limit_whitelist is not None:
        config["limit-whitelist"] = limit_whitelist
    if max_body_size is not None:
        config["max-body-size"] = max_body_size
    if owasp_modsecurity_crs is not None:
        config["owasp-modsecurity-crs"] = owasp_modsecurity_crs
    if owasp_modsecurity_custom_rules is not None:
        config["owasp-modsecurity-custom-rules"] = owasp_modsecurity_custom_rules
    if path_routes is not None:
        config["path-routes"] = path_routes
    if retry_errors is not None:
        config["retry-errors"] = retry_errors
    if rewrite_target is not None:
        config["rewrite-target"] = rewrite_target
    if rewrite_enabled is not None:
        config["rewrite-enabled"] = rewrite_enabled
    if service_namespace is not None:
        config["service-namespace"] = service_namespace
    if session_cookie_max_age is not None:
        config["session-cookie-max-age"] = session_cookie_max_age
    if tls_secret_name is not None:
        config["tls-secret-name"] = tls_secret_name

    _NginxRouteRequirer(
        charm=charm, config=config, nginx_route_relation_name=nginx_route_relation_name
    )


class _NginxRouteProvider(Object):
    """Class containing the functionality for the 'provides' side of the 'nginx-route' relation.

    Attrs:
        on: nginx-route relation event describer.

    Hook events observed:
        - relation-changed
    """

    on = NginxRouteCharmEvents()

    def __init__(
        self,
        charm: CharmBase,
        nginx_route_relation_name: str = "nginx-route",
    ):
        """Init function for the NginxRouterProvides class.

        Args:
            charm: The charm that provides the nginx-route relation.
            nginx_route_relation_name: Specifies the relation name of the relation handled by this
                provider class. The relation must have the nginx-route interface.
        """
        # Observe the relation-changed hook event and bind
        # self.on_relation_changed() to handle the event.
        super().__init__(charm, nginx_route_relation_name)
        self._charm = charm
        self._charm.framework.observe(
            self._charm.on[nginx_route_relation_name].relation_changed, self._on_relation_changed
        )
        self._charm.framework.observe(
            self._charm.on[nginx_route_relation_name].relation_broken, self._on_relation_broken
        )

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handle a change to the nginx-route relation.

        Confirm we have the fields we expect to receive.

        Args:
            event: Event triggering the relation-changed hook for the relation.
        """
        # `self.unit` isn't available here, so use `self.model.unit`.
        if not self._charm.model.unit.is_leader():
            return

        relation_name = event.relation.name

        if not event.relation.data[event.app]:
            logger.info(
                "%s hasn't finished configuring, waiting until relation is changed again.",
                relation_name,
            )
            return

        required_relation_fields = set(
            f["name"] for f in NGINX_ROUTE_RELATION_FIELDS if not f["optional"]
        )

        missing_fields = required_relation_fields - required_relation_fields

        if missing_fields:
            logger.warning(
                "Missing required data fields for %s relation: %s",
                relation_name,
                ", ".join(missing_fields),
            )
            self._charm.model.unit.status = BlockedStatus(
                f"Missing fields for {relation_name}: {', '.join(missing_fields)}"
            )
            return

        # Create an event that our charm can use to decide it's okay to
        # configure the Kubernetes Nginx ingress resources.
        self.on.nginx_route_available.emit()

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle a relation-broken event in the nginx-route relation.

        Args:
            event: Event triggering the relation-broken hook for the relation.
        """
        if not self._charm.model.unit.is_leader():
            return

        # Create an event that our charm can use to remove the Kubernetes Nginx ingress resources.
        self.on.nginx_route_broken.emit(event.relation)


# This is here only to maintain a reference to the instance of NginxRouteProvider created by
# the provide_nginx_route function. This is required for ops framework event handling to work.
# The provider instance will have the same lifetime as the charm that creates it.
__provider_references = weakref.WeakKeyDictionary()


def provide_nginx_route(
    charm: CharmBase,
    on_nginx_route_available: typing.Callable,
    on_nginx_route_broken: typing.Callable,
    nginx_route_relation_name: str = "nginx-route",
):
    """Set up nginx-route relation handlers on the provider side.

    This function must be invoked in the charm class constructor.

    Args:
        charm: The charm that requires the nginx-route relation.
        on_nginx_route_available: Callback function for the nginx-route-available event.
        on_nginx_route_broken: Callback function for the nginx-route-broken event.
        nginx_route_relation_name: Specifies the relation name of the relation handled by this
            provider class. The relation must have the nginx-route interface.
    """
    if __provider_references.get(charm, {}).get(nginx_route_relation_name) is not None:
        raise RuntimeError(
            "provide_nginx_route was invoked twice with the same nginx-route relation name"
        )
    provider = _NginxRouteProvider(
        charm=charm, nginx_route_relation_name=nginx_route_relation_name
    )
    if charm in __provider_references:
        __provider_references[charm][nginx_route_relation_name] = provider
    else:
        __provider_references[charm] = {nginx_route_relation_name: provider}
    charm.framework.observe(provider.on.nginx_route_available, on_nginx_route_available)
    charm.framework.observe(provider.on.nginx_route_broken, on_nginx_route_broken)
