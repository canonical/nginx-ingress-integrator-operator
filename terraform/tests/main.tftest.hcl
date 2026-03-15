# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

run "setup_tests" {
  module {
    source = "./tests/setup"
  }
}

run "basic_deploy" {
  variables {
    model_uuid = run.setup_tests.model_uuid
    channel    = "latest/edge"
    # renovate: depName="nginx-ingress-integrator"
    revision = 347
  }

  assert {
    condition     = output.app_name == "nginx-ingress-integrator"
    error_message = "nginx-ingress-integrator app_name did not match expected"
  }
}
