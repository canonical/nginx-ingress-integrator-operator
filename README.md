# Ingress Operator

## Description

This charm is intended to provide an ingress for sidecar charms using the
Operator Framework until such time as Juju can expose the relevant primitives
to enable charms to configure an ingress natively via Juju (e.g. with TLS as
required, with session affinity as required, allowing for upload of a given
size, etc.).

## Usage

TODO: Provide high-level usage, such as required config or relations

## Running the charm locally

To build the charm, run `charmcraft build`.

You'll need version 1.14 or later of Go (`go version` will confirm your current version), and a custom version of the Juju 2.9 branch, as below:

```
git clone -b demo-pebble https://github.com/benhoyt/juju
cd juju
make install
make microk8s-operator-update  # to make the microk8s image and push to Docker
export PATH="/home/${USER}/go/bin:$PATH"
juju bootstrap microk8s --no-gui
juju add-model ingress-test
```
Now from the directory where you've run `charmcraft build` as above:
```
juju deploy ./k8s-ingress.charm --resource placeholder-image='google/pause'
```
This is currently failing with the following error in `juju debug-log`.
```
unit-k8s-ingress-0: 05:12:02 INFO juju.worker.uniter awaiting error resolution for "config-changed" hook
unit-k8s-ingress-0: 05:12:03 ERROR unit.k8s-ingress/0.juju-log Uncaught exception while in charm code:
Traceback (most recent call last):
  File "./src/charm.py", line 80, in <module>
    main(CharmK8SIngressCharm)
  File "/var/lib/juju/agents/unit-k8s-ingress-0/charm/venv/ops/main.py", line 402, in main
    _emit_charm_event(charm, dispatcher.event_name)
  File "/var/lib/juju/agents/unit-k8s-ingress-0/charm/venv/ops/main.py", line 140, in _emit_charm_event
    event_to_emit.emit(*args, **kwargs)
  File "/var/lib/juju/agents/unit-k8s-ingress-0/charm/venv/ops/framework.py", line 278, in emit
    framework._emit(event)
  File "/var/lib/juju/agents/unit-k8s-ingress-0/charm/venv/ops/framework.py", line 722, in _emit
    self._reemit(event_path)
  File "/var/lib/juju/agents/unit-k8s-ingress-0/charm/venv/ops/framework.py", line 767, in _reemit
    custom_handler(event)
  File "./src/charm.py", line 75, in _on_config_changed
    self._get_pods()
  File "./src/charm.py", line 63, in _get_pods
    self.k8s_auth()
  File "./src/charm.py", line 59, in k8s_auth
    kubernetes.config.load_incluster_config()
  File "/var/lib/juju/agents/unit-k8s-ingress-0/charm/venv/kubernetes/config/incluster_config.py", line 118, in load_incluster_config
    InClusterConfigLoader(
  File "/var/lib/juju/agents/unit-k8s-ingress-0/charm/venv/kubernetes/config/incluster_config.py", line 54, in load_and_set
    self._load_config()
  File "/var/lib/juju/agents/unit-k8s-ingress-0/charm/venv/kubernetes/config/incluster_config.py", line 73, in _load_config
    raise ConfigException("Service token file does not exists.")
kubernetes.config.config_exception.ConfigException: Service token file does not exists.
unit-k8s-ingress-0: 05:12:03 ERROR juju.worker.uniter.operation hook "config-changed" (via hook dispatching script: dispatch) failed: exit status 1
```
Per https://github.com/kubernetes-client/python/issues/1331 the file it's looking for is
/var/run/secrets/kubernetes.io/serviceaccount/token, but this file isn't present in the
'charm' container for the deployed instance. The file does exist in the model operator, however.

This has been filed as https://bugs.launchpad.net/juju/+bug/1920102.

To work around this, we've added a `kube-config` config option. This should be the contents of your
kubernetes client configuration. If you're using microk8s you can get this via `microk8s config`,
and you'd then deploy the charm as follows:
```
juju deploy ./k8s-ingress.charm --resource placeholder-image='google/pause' --config kube-config="$(microk8s config)"
```

## Testing

Simply run `make test`.
