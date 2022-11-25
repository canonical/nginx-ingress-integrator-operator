# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""This code snippet is used to be loaded into any-charm which is used for integration tests."""

from any_charm_base import AnyCharmBase
from ingress import IngressRequires


class AnyCharm(AnyCharmBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ingress = IngressRequires(
            self,
            {
                "service-hostname": "any",
                "service-name": self.app.name,
                "service-port": 80,
                "owasp-modsecurity-crs": True,
            },
        )

    def update_ingress(self, ingress_config):
        self.ingress.update_config(ingress_config)
