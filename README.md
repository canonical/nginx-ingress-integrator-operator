# Nginx Ingress Integrator

A Juju charm deploying and managing external access to HTTP/HTTPS services in a
Kubernetes cluster via an Nginx Ingress resource. This requires the Kubernetes
cluster in question to have an Nginx Ingress Controller already deployed into it.

This charm simplifies exposing services running inside a Kubernetes cluster to
external clients. It offers TLS termination as well as easy configuration of a
number of advanced features including rate limiting, restricting access to
specific client IP source ranges, and OWASP ModSecurity Core Rule Set (CRS).

As such, the charm makes it easy for charm developers to provide external
access to their HTTP workloads in Kubernetes by easy integration offered via
[the charm's ingress library](https://charmhub.io/nginx-ingress-integrator/libraries/ingress).

For DevOps and SRE teams, providing ingress for charms that support a relation
to this charm will be possible via a simple `juju relate` command.

## Deployment options overview

For overall concepts related to using Juju
[see the Juju overview page](https://juju.is/). For easy local testing we
recommend
[this how to on using MicroK8s with Juju](https://juju.is/docs/olm/microk8s).
Because this charm requires an ingress controller, you'll also need to enable
the `ingress` add-on by running `microk8s enable ingress`.

## How to deploy this charm (quick guide)

To deploy the charm and relate it to
[the Hello Kubecon charm](https://charmhub.io/hello-kubecon) within a Juju Kubernetes model:

    juju deploy nginx-ingress-integrator
    juju deploy hello-kubecon
    juju relate nginx-ingress-integrator hello-kubecon
    # If your cluster has RBAC enabled you'll be prompted to run the following:
    juju trust nginx-ingress-integrator --scope cluster

Once the deployment has completed and the "hello-kubecon" workload state in
`juju status` has changed to "active" you can visit `http://hello-kubecon` in
a browser (assuming `hello-kubecon` resolves to the IP(s) of your k8s ingress).

## Project and community

The Nginx Ingress Integrator Operator is a member of the Ubuntu family. It's an
open source project that warmly welcomes community projects, contributions,
suggestions, fixes and constructive feedback.
* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Get support](https://discourse.charmhub.io/)
* [Join our online chat](https://chat.charmhub.io/charmhub/channels/charm-dev)
* [Contribute](https://charmhub.io/nginx-ingress-integrator/docs/contributing)
* [Roadmap](https://charmhub.io/nginx-ingress-integrator/docs/roadmap)
Thinking about using the Nginx Ingress Integrator for your next project? [Get in touch](https://chat.charmhub.io/charmhub/channels/charm-dev)!

---

For further details,
[see the charm's detailed documentation](https://charmhub.io/nginx-ingress-integrator/docs).
