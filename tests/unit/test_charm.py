# Copyright 2021 Tom Haddon
# See LICENSE file for licensing details.

import mock
import unittest

from ops.model import ActiveStatus
from ops.testing import Harness
from charm import CharmK8SIngressCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        """Setup the harness object."""
        self.harness = Harness(CharmK8SIngressCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @mock.patch('charm.CharmK8SIngressCharm._define_ingress')
    @mock.patch('charm.CharmK8SIngressCharm._define_service')
    def test_config_changed(self, _define_service, _define_ingress):
        """Test our config changed handler."""
        # Confirm our _define_ingress and _define_service methods haven't been called.
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # Test if config-changed is called with service-name empty, our methods still
        # aren't called.
        self.harness.update_config({"service-name": ""})
        self.assertEqual(_define_ingress.call_count, 0)
        self.assertEqual(_define_service.call_count, 0)
        # And now test if we set a service-name config, our methods are called.
        self.harness.update_config({"service-name": "gunicorn"})
        self.assertEqual(_define_ingress.call_count, 1)
        self.assertEqual(_define_service.call_count, 1)
        # Confirm status is as expected.
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())
