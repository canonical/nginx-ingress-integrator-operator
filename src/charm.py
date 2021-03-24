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

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    @property
    def _ingress_name(self):
        """Return an ingress name for use creating a k8s ingress."""
        # Follow the same naming convention as Juju.
        return "{}-ingress".format(self.config["service-name"])

    @property
    def _service_name(self):
        """Return a service name for the use creating a k8s service."""
        # Avoid collision with service name created by Juju.
        return "{}-service".format(self.config["service-name"])

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

    def _get_k8s_service(self):
        """Get a K8s service definition."""
        return kubernetes.client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=kubernetes.client.V1ObjectMeta(name=self._service_name),
            spec=kubernetes.client.V1ServiceSpec(
                selector={"app.kubernetes.io/name": self.config["service-name"]},
                ports=[
                    kubernetes.client.V1ServicePort(
                        name="tcp-{}".format(self.config["service-port"]),
                        port=self.config["service-port"],
                        target_port=self.config["service-port"],
                    )
                ],
            ),
        )

    def _get_k8s_ingress(self):
        """Get a K8s ingress definition."""
        return kubernetes.client.NetworkingV1beta1Ingress(
            api_version="networking.k8s.io/v1beta1",
            kind="Ingress",
            metadata=kubernetes.client.V1ObjectMeta(
                name=self._ingress_name,
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
                                        service_name=self._service_name,
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
        )

    def _define_service(self):
        """Create or update a service in kubernetes."""
        self.k8s_auth()
        api = _core_v1_api()
        body = self._get_k8s_service()
        services = api.list_namespaced_service(namespace=self.config["service-namespace"])
        if self._service_name in [x.metadata.name for x in services.items]:
            # Currently failing with port[1].name required but we're only
            # defining one port above...
            # api.patch_namespaced_service(
            #    name=service_name,
            #    namespace=self.config["service-namespace"],
            #    body=body,
            # )
            api.delete_namespaced_service(
                name=self._service_name,
                namespace=self.config["service-namespace"],
            )
            api.create_namespaced_service(
                namespace=self.config["service-namespace"],
                body=body,
            )
            logger.info(
                "Service updated in namespace %s with name %s",
                self.config["service-namespace"],
                self.config["service-name"],
            )
        else:
            api.create_namespaced_service(
                namespace=self.config["service-namespace"],
                body=body,
            )
            logger.info(
                "Service created in namespace %s with name %s",
                self.config["service-namespace"],
                self.config["service-name"],
            )

    def _define_ingress(self):
        """Create or update an ingress in kubernetes."""
        self.k8s_auth()
        api = _networking_v1_beta1_api()
        body = self._get_k8s_ingress()
        ingresses = api.list_namespaced_ingress(namespace=self.config["service-namespace"])
        if self._ingress_name in [x.metadata.name for x in ingresses.items]:
            api.patch_namespaced_ingress(
                name=self._ingress_name,
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
        """Handle the config changed event."""
        if self.config["service-name"]:
            self._define_service()
            self._define_ingress()
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(CharmK8SIngressCharm)
