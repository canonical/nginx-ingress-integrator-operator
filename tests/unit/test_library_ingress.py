# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from charms.nginx_ingress_integrator.v0.ingress import IngressRequires

from ops.charm import CharmBase
from ops.testing import Harness


class NginxIngressConsumerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.ingress = IngressRequires(self, {})


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(
            NginxIngressConsumerCharm,
            meta="""
            name: ingress-consumer
            requires:
              ingress:
                interface: ingress
        """,
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_config_dict_errors(self):
        log_message = (
            "ERROR:charms.nginx_ingress_integrator.v0.ingress:Ingress relation error, "
            "missing required key(s) in config dictionary: service-hostname, service-name, "
            "service-port"
        )
        with self.assertLogs(level='ERROR') as logger:
            self.assertTrue(self.harness.charm.ingress._config_dict_errors())
            self.assertEqual(sorted(logger.output), [log_message])

    def test_update_config(self):
        log_message = (
            "ERROR:charms.nginx_ingress_integrator.v0.ingress:Ingress relation error, "
            "unknown key(s) in config dictionary found: unknown-field"
        )
        with self.assertLogs(level='ERROR') as logger:
            # First check if we're not the leader nothing is logged.
            self.harness.set_leader(False)
            self.harness.charm.ingress.update_config({"unknown-field": "unknown-value"})
            self.assertEqual(sorted(logger.output), [])
            # We need to be the leader for the update_config function to do anything.
            self.harness.set_leader(True)
            # This will call _config_dict_errors for us, so we don't need to call it
            # manually.
            self.harness.charm.ingress.update_config({"unknown-field": "unknown-value"})
            self.assertEqual(sorted(logger.output), [log_message])
