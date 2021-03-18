#!/usr/bin/env python3
# Copyright 2021 Tom Haddon
# See LICENSE file for licensing details.

"""Charm the service.

Refer to the following post for a quick-start guide that will help you
develop a new k8s charm using the Operator Framework:

    https://discourse.charmhub.io/t/4208
"""

import logging

from kubernetes import client, config

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus
from ops.framework import StoredState

logger = logging.getLogger(__name__)


class CharmK8SIngressCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self._stored.set_default(things=[])

    def _get_pods(self):
        # Taken from https://github.com/kubernetes-client/python/blob/master/examples/in_cluster_config.py
        # however, currently getting https://pastebin.ubuntu.com/p/knFQhGyjYt/.
        # Not sure if this is due to permissions, but need to dig in more and
        # find out how to resolve this one way or the other.
        config.load_incluster_config()

        v1 = client.CoreV1Api()
        logger.info("Listing pods with their IPs:")
        ret = v1.list_pod_for_all_namespaces(watch=False)
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
