# Copyright 2021 Tom Haddon
# See LICENSE file for licensing details.

import mock
import unittest

from ops.testing import Harness
from charm import CharmK8SIngressCharm


class TestCharm(unittest.TestCase):
    @mock.patch('charm.CharmK8SIngressCharm._define_ingress')
    @mock.patch('charm.CharmK8SIngressCharm._define_service')
    def test_config_changed(self, _define_service, _define_ingress):
        harness = Harness(CharmK8SIngressCharm)
        self.addCleanup(harness.cleanup)
        harness.begin()
        self.assertEqual(list(harness.charm._stored.things), [])
        harness.update_config({"thing": "foo"})
        self.assertEqual(list(harness.charm._stored.things), ["foo"])
