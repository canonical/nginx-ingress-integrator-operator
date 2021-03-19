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
        if self._authed:
            return

        _fix_lp_1892255()
        kubernetes.config.load_incluster_config()
        self._authed = True

    def _get_pods(self):
        self.k8s_auth()
        api = _core_v1_api()
        logger.info("Listing pods with their IPs:")
        ret = api.list_pod_for_all_namespaces(watch=False)
        for i in ret.items:
            logger.info("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))

    def _on_config_changed(self, _):
        current = self.config["thing"]
        if current not in self._stored.things:
            logger.debug("found a new thing: %r", current)
            self._stored.things.append(current)
        self._get_pods()
        self.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(CharmK8SIngressCharm)
