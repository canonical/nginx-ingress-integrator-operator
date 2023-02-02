# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import itertools
import unittest

import yaml
from charms.nginx_ingress_integrator.v0.ingress import (  # type: ignore[import]
    OPTIONAL_INGRESS_RELATION_FIELDS,
    RELATION_INTERFACES_MAPPINGS,
    REQUIRED_INGRESS_RELATION_FIELDS,
    IngressRequires,
)
from ops.charm import CharmBase
from ops.testing import Harness


class NginxIngressConsumerCharm(CharmBase):
    def __init__(self, *args, config_dict=None):
        super().__init__(*args)
        self.ingress = IngressRequires(self, config_dict or {})


META = yaml.dump({"name": "ingress-consumer", "requires": {"ingress": {"interface": "ingress"}}})


class TestCharmInit(unittest.TestCase):
    """Tests for constructing the NginxIngressConsumerCharm."""

    def test_empty(self):
        """
        arrange: given an empty configuration
        act: when the charm is constructed with the configuration
        assert: then the default value is set.
        """
        config_dict: dict[str, str] = {}

        class CharmWithConfigDict(NginxIngressConsumerCharm):
            def __init__(self, *args):
                super().__init__(*args, config_dict=config_dict)

        self.harness = Harness(CharmWithConfigDict, meta=META)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.assertEqual(
            self.harness.charm.ingress.config_dict["service-namespace"], self.harness.model.name
        )

    def test_with_service_namespace(self):
        """
        arrange: given a configuration with the service namespace provided
        act: when the charm is constructed with the configuration
        assert: then the service namespace from the configuration is used.
        """
        service_namespace = "service namespace 1"
        config_dict = {"service-namespace": service_namespace}

        class CharmWithConfigDict(NginxIngressConsumerCharm):
            def __init__(self, *args):
                super().__init__(*args, config_dict=config_dict)

        self.harness = Harness(CharmWithConfigDict, meta=META)  # type: ignore[arg-type]
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.assertEqual(
            self.harness.charm.ingress.config_dict["service-namespace"], service_namespace
        )
        self.assertEqual(self.harness.charm.ingress.config_dict["model"], service_namespace)

    def test_with_previous_config(self):
        """
        arrange: given a configuration with all the items pre-standard
        act: when the charm is constructed with the configuration
        assert: then the configuration is stored with the previous and new keys.
        """
        service_hostname = "service hostname 1"
        service_name = "service name 1"
        service_port = "service port 1"
        service_namespace = "service namespace 1"
        config_dict = {
            "service-hostname": service_hostname,
            "service-name": service_name,
            "service-port": service_port,
            "service-namespace": service_namespace,
        }

        class CharmWithConfigDict(NginxIngressConsumerCharm):
            def __init__(self, *args):
                super().__init__(*args, config_dict=config_dict)

        self.harness = Harness(CharmWithConfigDict, meta=META)  # type: ignore[arg-type]
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.assertEqual(
            self.harness.charm.ingress.config_dict["service-hostname"], service_hostname
        )
        self.assertEqual(self.harness.charm.ingress.config_dict["service-name"], service_name)
        self.assertEqual(self.harness.charm.ingress.config_dict["service-port"], service_port)
        self.assertEqual(
            self.harness.charm.ingress.config_dict["service-namespace"], service_namespace
        )

        self.assertEqual(self.harness.charm.ingress.config_dict["host"], service_hostname)
        self.assertEqual(self.harness.charm.ingress.config_dict["name"], service_name)
        self.assertEqual(self.harness.charm.ingress.config_dict["port"], service_port)
        self.assertEqual(self.harness.charm.ingress.config_dict["model"], service_namespace)

    def test_with_new_config(self):
        """
        arrange: given a configuration with all the items based on the new standard
        act: when the charm is constructed with the configuration
        assert: then the configuration is stored with the new keys.
        """
        service_hostname = "service hostname 1"
        service_name = "service name 1"
        service_port = "service port 1"
        service_namespace = "service namespace 1"
        config_dict = {
            "host": service_hostname,
            "name": service_name,
            "port": service_port,
            "model": service_namespace,
        }

        class CharmWithConfigDict(NginxIngressConsumerCharm):
            def __init__(self, *args):
                super().__init__(*args, config_dict=config_dict)

        self.harness = Harness(CharmWithConfigDict, meta=META)  # type: ignore[arg-type]
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.assertEqual(self.harness.charm.ingress.config_dict["host"], service_hostname)
        self.assertEqual(self.harness.charm.ingress.config_dict["name"], service_name)
        self.assertEqual(self.harness.charm.ingress.config_dict["port"], service_port)
        self.assertEqual(self.harness.charm.ingress.config_dict["model"], service_namespace)


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(
            NginxIngressConsumerCharm,
            meta=META,
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_config_dict_empty(self):
        """
        arrange: given empty configuration
        act: when _config_dict_errors is called
        assert: then True is returned and a message with the missing configuration is logged.
        """
        with self.assertLogs(level="ERROR") as logger:
            result = self.harness.charm.ingress._config_dict_errors({})

            self.assertTrue(result)

            logged_output = "\n".join(logger.output)
            self.assertIn(
                "ERROR:charms.nginx_ingress_integrator.v0.ingress:Ingress relation error",
                logged_output,
            )
            self.assertIn("service-hostname", logged_output)
            self.assertIn("service-name", logged_output)
            self.assertIn("service-port", logged_output)

    def test_config_dict_unknown(self):
        """
        arrange: given configuration with an unknown key
        act: when _config_dict_errors is called
        assert: then True is returned and a message with the unknown configuration is logged.
        """
        unknown_key = "unknown_key"
        self.harness.charm.ingress.config_dict[unknown_key] = "unknown value"

        with self.assertLogs(level="ERROR") as logger:
            result = self.harness.charm.ingress._config_dict_errors(
                self.harness.charm.ingress.config_dict
            )

            self.assertTrue(result)

            logged_output = "\n".join(logger.output)
            self.assertIn(unknown_key, logged_output)

    def test_config_dict_valid(self):
        """
        arrange: given configuration with all valid keys
        act: when _config_dict_errors is called
        assert: False is returned.
        """
        for key in itertools.chain(
            REQUIRED_INGRESS_RELATION_FIELDS,
            OPTIONAL_INGRESS_RELATION_FIELDS,
            RELATION_INTERFACES_MAPPINGS.values(),
        ):
            self.harness.charm.ingress.config_dict[key] = key

        result = self.harness.charm.ingress._config_dict_errors(
            self.harness.charm.ingress.config_dict
        )
        self.assertFalse(result)

    def test_update_config(self):
        log_message = (
            "ERROR:charms.nginx_ingress_integrator.v0.ingress:Ingress relation error, "
            "unknown key(s) in config dictionary found: unknown-field"
        )
        with self.assertLogs(level="ERROR") as logger:
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
