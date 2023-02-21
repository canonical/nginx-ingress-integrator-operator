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
```
from charms.nginx_ingress_integrator.v0.nginx_route import NginxRouteRequirer

# In your charm's `__init__` method.
require_nginx_route(self, {
        "service-hostname": self.config["external_hostname"],
        "service-name": self.app.name,
        "service-port": 80,
    }
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


class NginxRouteRequirer(Object):
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

    def _check_config_dict_errors(self) -> None:
        """Check our config dict for errors."""
        config_keys = self._config.keys()
        unknown = config_keys - set(i["name"] for i in NGINX_ROUTE_RELATION_FIELDS)
        required_keys = set(i["name"] for i in NGINX_ROUTE_RELATION_FIELDS if not i["optional"])
        missing = required_keys - config_keys
        if unknown:
            raise KeyError(
                "nginx-route relation error, unknown key(s) in config dictionary found: %s",
                ", ".join(unknown),
            )
        if missing:
            raise KeyError(
                "nginx-route relation error, missing required key(s) in config dictionary: %s",
                ", ".join(sorted(missing)),
            )

    def _config_reconciliation(self, _event):
        """Update the nginx-route relation data to be exactly as defined by config."""
        if not self._charm.model.unit.is_leader():
            return
        self._check_config_dict_errors()
        for relation in self._charm.model.relations[self._nginx_route_relation_name]:
            relation_app_data = relation.data[self._charm.app]
            delete_keys = set(r for r in relation_app_data if r not in self._config)
            for delete_key in delete_keys:
                del relation_app_data[delete_key]
            for relation_field, relation_data_value in self._config.items():
                relation_app_data[relation_field] = str(relation_data_value)


def require_nginx_route(
    charm: CharmBase,
    config: typing.Dict[str, typing.Union[str, int, bool]],
    nginx_route_relation_name: str = "nginx-route",
):
    """Set up nginx-route relation handlers on the requirer side.

    This function must be invoked in the charm class constructor.

    Args:
        charm: The charm that requires the nginx-route relation.
        config: Contains all the configuration options for nginx-route.
        nginx_route_relation_name: Specifies the relation name of the relation handled by this
            requirer class. The relation must have the nginx-route interface.
    """
    NginxRouteRequirer(
        charm=charm, config=config, nginx_route_relation_name=nginx_route_relation_name
    )


class NginxRouteProvider(Object):
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
    provider = NginxRouteProvider(charm=charm, nginx_route_relation_name=nginx_route_relation_name)
    if charm in __provider_references:
        __provider_references[charm][nginx_route_relation_name] = provider
    else:
        __provider_references[charm] = {nginx_route_relation_name: provider}
    charm.framework.observe(provider.on.nginx_route_available, on_nginx_route_available)
    charm.framework.observe(provider.on.nginx_route_broken, on_nginx_route_broken)
