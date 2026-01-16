# Charm architecture

At its core, Nginx Ingress Integrator is a basic charm that talks to the 
Kubernetes API and provisions an Nginx ingress resource.

In designing this charm, we've leveraged the [sidecar](https://kubernetes.io/blog/2015/06/the-distributed-system-toolkit-patterns/#example-1-sidecar-containers) pattern for Kubernetes 
charms, but somewhat unusually we're not actually deploying a workload container
alongside our charm code. Instead, the charm code talks directly to the 
Kubernetes API to provision the appropriate Nginx ingress resource to enable 
traffic to reach the service in question. 

As a result, if you run a `kubectl get pods` on a namespace named for the Juju 
model you’ve deployed the nginx-ingress-integrator charm into, you’ll see 
something like the following:

```
NAME                             READY   STATUS    RESTARTS   AGE
nginx-ingress-integrator-0       1/1     Running   0          3h47m

```

This shows there is only one container for the charm code itself.

## Structure of the charm

The Nginx Ingress Integrator receives ingress requests from application charms 
via either the [`ingress` integration](https://github.com/canonical/charm-relation-interfaces/tree/main/interfaces/ingress/v2) 
or the [`nginx-route` integration](https://github.com/canonical/charm-relation-interfaces/tree/main/interfaces/nginx_route/v0). 
The `ingress` integration is more prevalent, as it is the same integration 
supported by many other charms, including the [`traefik-k8s` charm](https://charmhub.io/traefik-k8s). 
The `nginx-route` integration is more specific to the Nginx Ingress Integrator 
but offers more customization of the ingress specification.

When the Nginx Ingress Integrator receives an ingress request from an application charm, via either the 
`ingress` integration or the `nginx-route` integration, it unifies the request
into an intermediate representation and then converts this 
representation into the desired Kubernetes resources, including [`ingress` resources](https://kubernetes.io/docs/concepts/services-networking/ingress/)
, [`service` resources](https://kubernetes.io/docs/concepts/services-networking/service/)
, [`EndpointSlice` resources](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/)
, and [`secret` resources](https://kubernetes.io/docs/concepts/configuration/secret/)
, among others. This process creates the ingress needed to route traffic to the 
application charm as requested.

The Nginx Ingress Integrator can also integrate with `tls-certificate` provider 
charms and use the certificates provided by these charms as the server 
certificates for ingress.

### Handling of `ingress` integration

The `ingress` integration is a universal integration that may be used in 
Juju VM models or Juju Kubernetes models, unlike the `nginx-route` integration, 
which is designed exclusively for use within Juju Kubernetes models. Therefore, the Nginx
Ingress Integrator cannot make many assumptions about the application requiring
ingress. For this reason, the ingress for `ingress` integrations is built based
on Kubernetes `EndpointSlice` resources, using `IP` addresses provided in the
ingress integration. In contrast, the `nginx-route` integration is based on 
`service` resources with [selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/).

## OCI images

Nginx Ingress Integrator charm doesn't use any OCI image resources.

## Juju events

For this charm, the following Juju events are observed:

1. [`config-changed`](https://canonical-juju.readthedocs-hosted.com/en/latest/user/reference/hook/#config-changed)
2. [`start`](https://canonical-juju.readthedocs-hosted.com/en/latest/user/reference/hook/#start)
3. [`get-certificate-action`](https://canonical-juju.readthedocs-hosted.com/en/latest/user/reference/hook/#action-action)
4. [`data-provided` from `ingress` charm library](https://charmhub.io/traefik-k8s/libraries/ingress)
5. [`data-removed` from `ingress` charm library](https://charmhub.io/traefik-k8s/libraries/ingress)
6. [`certificate_available` from `tls_certificates` charm library](https://charmhub.io/tls-certificates-interface/libraries/tls_certificates)

In addition, the charm libraries can observe many other events. For more 
details, see the documentation for the charm libraries.

## Charm code overview

The `src/charm.py` is the default entry point for a charm and has the 
`NginxIngressCharm` Python class which inherits from `CharmBase`. `CharmBase` is 
the base class from which all Charms are formed, defined by [Ops](https://juju.is/docs/sdk/ops)
(Python framework for developing charms).

> See more in the Juju docs: [Charm](https://documentation.ubuntu.com/juju/3.6/reference/charm/)

The `__init__` method guarantees that the charm observes all events relevant to 
its operation and handles them.

Take, for example, when a configuration is changed by using the CLI.

1. User runs the configuration command:
```bash
juju config <relevant-charm-configuration>
```
2. A `config-changed` event is emitted.
3. In the `__init__` method is defined how to handle this event like this:
```python
self.framework.observe(self.on.config_changed, self._on_config_changed)
```
4. The method `_on_config_changed`, for its turn, will take the necessary actions such as waiting for all the relations to be ready and then configuring the containers.

## Charm architecture diagram

The Nginx Ingress Integrator charm uses the `ingress`, `tls_certificates` and 
`nginx_route` charm libraries to handle charm integrations. It also uses the 
Kubernetes Python client, which is wrapped in custom modules to reconcile the 
Kubernetes resources necessary for ingress.

```mermaid
C4Context
    System_Boundary(nginx-ingress-integrator, "Nginx Ingress Integrator") {
        Container_Boundary(charm-lib, "Charm Libraries") {
            Component(nginx-route-lib, "nginx_ingress_integrator.v0.nginx_route")
            Component(tls-certificates-lib, "charmlibs.interfaces.tls_certificates")
            Component(ingress-lib, "traefik_k8s.v2.ingress")
        }
        
        Container_Boundary(charm, "Charm Logic") {
            Component(nginx-ingress-integrator-charm, "Nginx Ingress Integrator Charm")
        }
        
        Container_Boundary(kubernetes-lib, "Kubernetes Libraries") {
            Component(endpoint-slice, "EndpointSlice")
            Component(endpoint, "Endpoint")
            Component(ingress, "Ingress")
            Component(secret, "Secret")
            Component(service, "Service")
        }
        
        Rel(nginx-route-lib, nginx-ingress-integrator-charm, "Ingress Spec")
        Rel(tls-certificates-lib, nginx-ingress-integrator-charm, "Server Cert")
        Rel(ingress-lib, nginx-ingress-integrator-charm, "Ingress Spec")
        Rel(nginx-ingress-integrator-charm, endpoint-slice, "Reconciliation")
        Rel(nginx-ingress-integrator-charm, endpoint, "Reconciliation")
        Rel(nginx-ingress-integrator-charm, ingress, "Reconciliation")
        Rel(nginx-ingress-integrator-charm, secret, "Reconciliation")
        Rel(nginx-ingress-integrator-charm, service, "Reconciliation")

        UpdateLayoutConfig($c4ShapeInRow="1", $c4BoundaryInRow="4")
        
        UpdateRelStyle(nginx-route-lib, nginx-ingress-integrator-charm , $offsetY="-15", $offsetX="-5")
        UpdateRelStyle(tls-certificates-lib, nginx-ingress-integrator-charm, $offsetY="0", $offsetX="-120")
        UpdateRelStyle(ingress-lib, nginx-ingress-integrator-charm, $offsetY="70", $offsetX="-140")
        UpdateRelStyle(nginx-ingress-integrator-charm, endpoint-slice, $offsetY="-10", $offsetX="-20")
    }
```