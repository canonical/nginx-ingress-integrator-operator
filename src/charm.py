#!/usr/bin/env python3
# Copyright 2021 Tom Haddon
# See LICENSE file for licensing details.

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""

import logging
import os
from pathlib import Path

import kubernetes

# from kubernetes.client.rest import ApiException as K8sApiException

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus
from ops.framework import StoredState

logger = logging.getLogger(__name__)


def _core_v1_api():
    """Use the v1 k8s API."""
    cl = kubernetes.client.ApiClient()
    return kubernetes.client.CoreV1Api(cl)


def _networking_v1_beta1_api():
    """Use the v1 beta1 networking API."""
    return kubernetes.client.NetworkingV1beta1Api()


def _fix_lp_1892255():
    """Workaround for lp:1892255."""
    # Remove os.environ.update when lp:1892255 is FIX_RELEASED.
    os.environ.update(
        dict(e.split("=") for e in Path("/proc/1/environ").read_text().split("\x00") if "KUBERNETES_SERVICE" in e)
    )


class CharmK8SIngressCharm(CharmBase):
    """Charm the service."""

    _authed = False
    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self._stored.set_default(things=[])

    def k8s_auth(self):
        """Authenticate to kubernetes."""
        if self._authed:
            return

        _fix_lp_1892255()

        # Work around for lp#1920102 - allow the user to pass in k8s config manually.
        if self.config["kube-config"]:
            with open('/kube-config', 'w') as kube_config:
                kube_config.write(self.config["kube-config"])
            kubernetes.config.load_kube_config(config_file='/kube-config')
        else:
            kubernetes.config.load_incluster_config()

        self._authed = True

    def _create_ingress(self):
        """Create an ingress in kubernetes."""
        self.k8s_auth()
        api = _networking_v1_beta1_api()

        # Follow the same naming convention as Juju.
        ingress_name = "{}-ingress".format(self.config["service-name"])

        body = kubernetes.client.NetworkingV1beta1Ingress(
            api_version="networking.k8s.io/v1beta1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=ingress_name,
                annotations={
                    "nginx.ingress.kubernetes.io/rewrite-target": "/",
                    "nginx.ingress.kubernetes.io/ssl-redirect": "false",
                },
            ),
            spec=kubernetes.client.NetworkingV1beta1IngressSpec(
                rules=[
                    kubernetes.client.NetworkingV1beta1IngressRule(
                        host=self.config["service-hostname"],
                        http=kubernetes.client.NetworkingV1beta1HTTPIngressRuleValue(
                            paths=[
                                kubernetes.client.NetworkingV1beta1HTTPIngressPath(
                                    path="/",
                                    backend=kubernetes.client.NetworkingV1beta1IngressBackend(
                                        service_port=self.config["service-port"],
                                        service_name=self.config["service-name"],
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
        )
        ingresses = api.list_namespaced_ingress(namespace=self.config["service-namespace"])
        if ingress_name in [x.metadata.name for x in ingresses.items]:
            api.patch_namespaced_ingress(
                name=ingress_name,
                namespace=self.config["service-namespace"],
                body=body,
            )
            logger.info(
                "Ingress updated in namespace %s with name %s",
                self.config["service-namespace"],
                self.config["service-name"],
            )
        else:
            api.create_namespaced_ingress(
                namespace=self.config["service-namespace"],
                body=body,
            )
            logger.info(
                "Ingress created in namespace %s with name %s",
                self.config["service-namespace"],
                self.config["service-name"],
            )

    def _on_config_changed(self, _):
        current = self.config["thing"]
        if current not in self._stored.things:
            logger.debug("found a new thing: %r", current)
            self._stored.things.append(current)
        if self.config["service-name"]:
            self._create_ingress()
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(CharmK8SIngressCharm)
