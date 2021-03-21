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
We've also added some initial config options to configure the ingress. As an
example:
```
juju config k8s-ingress service-namespace=ingress-test service-name=gunicorn service-port=80 service-hostname=foo.internal
```
This will give you something like this (deployed alongside the non-sidecar
version of the charm for comparison):
```
mthaddon@tenaya:~/repos/charm-k8s-ingress/charm-k8s-ingress$ microk8s.kubectl get ingress --all-namespaces
NAMESPACE      NAME                   CLASS    HOSTS          ADDRESS   PORTS   AGE
ingress-test   gunicorn-old-ingress   <none>   foo.internal             80      27m
ingress-test   gunicorn-ingress       <none>   foo.internal             80      91s
mthaddon@tenaya:~/repos/charm-k8s-ingress/charm-k8s-ingress$ juju status
Model         Controller          Cloud/Region        Version  SLA          Timestamp
ingress-test  microk8s-localhost  microk8s/localhost  2.9-rc7  unsupported  18:12:17+01:00

App           Version            Status  Scale  Charm        Store  Channel  Rev  OS          Address        Message
gunicorn                         active      1  gunicorn     local             3  ubuntu
gunicorn-old  gunicorn-app:edge  active      1  gunicorn     local             1  kubernetes  10.152.183.69
k8s-ingress                      active      1  k8s-ingress  local             3  ubuntu

Unit             Workload  Agent  Address      Ports   Message
gunicorn-old/1*  active    idle   10.1.234.25  80/TCP
gunicorn/0*      active    idle   10.1.234.21
k8s-ingress/0*   active    idle   10.1.234.28

mthaddon@tenaya:~/repos/charm-k8s-ingress/charm-k8s-ingress$ microk8s.kubectl describe ingress -n ingress-test gunicorn-ingress
Name:             gunicorn-ingress
Namespace:        ingress-test
Address:
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host          Path  Backends
  ----          ----  --------
  foo.internal  
                /   gunicorn:80 ()
Annotations:    nginx.ingress.kubernetes.io/rewrite-target: /
Events:         <none>
mthaddon@tenaya:~/repos/charm-k8s-ingress/charm-k8s-ingress$ microk8s.kubectl describe ingress -n ingress-test gunicorn-old-ingress
Name:             gunicorn-old-ingress
Namespace:        ingress-test
Address:
Default backend:  default-http-backend:80 (<error: endpoints "default-http-backend" not found>)
Rules:
  Host          Path  Backends
  ----          ----  --------
  foo.internal  
                /   gunicorn-old:80 (10.1.234.25:80)
Annotations:    controller.juju.is/id: ac6cacf4-3ed5-4313-88d2-89eef6ae5822
                model.juju.is/id: 5cbdb63d-0847-4b92-8c4b-f4af185b60b0
                nginx.ingress.kubernetes.io/ssl-redirect: false
Events:         <none>
mthaddon@tenaya:~/repos/charm-k8s-ingress/charm-k8s-ingress$ 
```
This needs further work and testing, but produces an initial ingress.

## Testing

Simply run `make test`.
