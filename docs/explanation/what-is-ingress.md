Ingress in the Kubernetes context is [defined as](https://kubernetes.io/docs/concepts/services-networking/ingress/) “An API object that manages external access to the services in a cluster, typically HTTP. Ingress may provide load balancing, SSL termination and name-based virtual hosting.”

In the context of this operator, there are two key concepts to understand:

* The first is an ingress **controller**, which is a cluster-level service that provides ingress for applications.
* The second is an ingress **resource**, which is something defined by an application running within a cluster describing how ingress for it should be configured.

This operator configures an ingress **resource** which is then picked up by an ingress **controller** to determine how the ingress for a given application is configured.

### What does this charm do?

To enable ingress via Nginx for [sidecar charms](https://discourse.charmhub.io/t/the-future-of-charmed-operators-on-kubernetes/4361), we’ve created this nginx-ingress-integrator charm. To use this charm you’ll need to have an Nginx Ingress Controller deployed into your K8s cluster.

The charm can be configured via a relation, or via `juju config` directly. See the [ingress library documentation](https://charmhub.io/nginx-ingress-integrator/libraries/ingress) for more details on an easy method to integrate other charms.

The reason for offering both relation and direct `juju config` support is that providing the relation means charm authors can make the experience better for end users by implementing the relation. If a charm doesn’t implement the relation it can still be used with this charm and configured manually.

Using the relation, the charm supports the following features:
* Rate limiting (with an allowlist for exclusions by a CIDR).
* Setting maximum allowed body size for file uploads.
* Configuring retrying of errors against the next server.
* A session cookie to use for cookie-based session affinity, and the age of that cookie.
* The TLS certificate to use for your service if applicable.

All of these options can also be configured at the time of deployment. In addition there’s an `ingress-class` option to use when your cluster has multiple ingress controllers. This allows you to target the correct controller.
