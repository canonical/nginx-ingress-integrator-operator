"""Library for the ingress relation.

This library contains the Requires and Provides classes for handling
the ingress interface.

Import `IngressProvides` in your charm, with required options:
    - "self" (the charm itself)
    - service_hostname
    - service_name
    - service_port
Optionally you can also pass:
    - max_body_size
    - service_namespace
    - session_cookie_max_age
    - tls_secret_name

As an example:
```
from charms.ingress.v0.ingress import IngressProvides

# In your charm's `__init__` method.
self.ingress = IngressProvides(self, self.config["external_hostname"], self.app.name, 80)
```
"""

import logging

from ops.framework import EventBase, Object
from ops.model import BlockedStatus

# The unique Charmhub library identifier, never change it
LIBID = "2d35a009b0d64fe186c99a8c9e53c6ab"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft push-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 3

logger = logging.getLogger(__name__)

REQUIRED_INGRESS_RELATION_FIELDS = {
    "service-hostname",
    "service-name",
    "service-port",
}

OPTIONAL_INGRESS_RELATION_FIELDS = {
    "max-body-size",
    "service-namespace",
    "session-cookie-max-age",
    "tls-secret-name",
}


class IngressAvailableEvent(EventBase):
    pass


class IngressProvides(Object):
    """This class defines the functionality for the 'provides' side of the 'ingress' relation.

    Hook events observed:
        - relation-changed
    """

    def __init__(
        self,
        charm,
        service_hostname,
        service_name,
        service_port,
        *,
        max_body_size=0,
        service_namespace="",
        session_cookie_max_age=0,
        tls_secret_name=""
    ):
        super().__init__(charm, "ingress")

        self.framework.observe(charm.on["ingress"].relation_changed, self._on_relation_changed)
        self.charm = charm

        # Ingress properties - Required.
        self.service_hostname = service_hostname
        self.service_name = service_name
        self.service_port = service_port

        # Ingress properties - Optional.
        self.max_body_size = max_body_size
        self.service_namespace = service_namespace
        self.session_cookie_max_age = session_cookie_max_age
        self.tls_secret_name = tls_secret_name

    def _on_relation_changed(self, event):
        """Handle the relation-changed event."""
        # `self.unit` isn't available here, so use `self.model.unit`.
        if self.model.unit.is_leader():
            # Required.
            event.relation.data[self.model.app]["service-hostname"] = self.service_hostname
            event.relation.data[self.model.app]["service-name"] = self.service_name
            event.relation.data[self.model.app]["service-port"] = str(self.service_port)
            # Optional.
            if self.max_body_size:
                event.relation.data[self.model.app]["max-body-size"] = str(self.max_body_size)
            if self.service_namespace:
                event.relation.data[self.model.app]["service-namespace"] = self.service_namespace
            if self.session_cookie_max_age:
                event.relation.data[self.model.app]["session-cookie-max-age"] = self.session_cookie_max_age
            if self.tls_secret_name:
                event.relation.data[self.model.app]["tls-secret-name"] = self.tls_secret_name


class IngressRequires(Object):
    """This class defines the functionality for the 'requires' side of the 'ingress' relation.

    Hook events observed:
        - relation-changed
    """

    def __init__(self, charm):
        super().__init__(charm, "ingress")
        # Observe the relation-changed hook event and bind
        # self.on_relation_changed() to handle the event.
        self.framework.observe(charm.on["ingress"].relation_changed, self._on_relation_changed)
        self.charm = charm

    def _on_relation_changed(self, event):
        """Handle a change to the ingress relation.

        Confirm we have the fields we expect to receive."""
        # `self.unit` isn't available here, so use `self.model.unit`.
        if not self.model.unit.is_leader():
            return

        ingress_data = {
            field: event.relation.data[event.app].get(field)
            for field in REQUIRED_INGRESS_RELATION_FIELDS | OPTIONAL_INGRESS_RELATION_FIELDS
        }

        missing_fields = sorted(
            [field for field in REQUIRED_INGRESS_RELATION_FIELDS if ingress_data.get(field) is None]
        )

        if missing_fields:
            logger.error("Missing required data fields for ingress relation: {}".format(", ".join(missing_fields)))
            self.model.unit.status = BlockedStatus("Missing fields for ingress: {}".format(", ".join(missing_fields)))

        # Create an event that our charm can use to decide it's okay to
        # configure the ingress.
        self.charm.on.ingress_available.emit()
