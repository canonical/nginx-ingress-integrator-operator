---
myst:
  html_meta:
    "description lang=en": "Learn how to deploy, configure and operate the NGINX ingress integrator charm using Juju."
---

# NGINX ingress integrator charm

A [Juju](https://juju.is/) [charm](https://documentation.ubuntu.com/juju/3.6/reference/charm/) deploying and managing external access to HTTP/HTTPS services in a Kubernetes cluster via an Nginx Ingress resource. This requires the Kubernetes cluster in question to have an [Nginx Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/) already deployed into it.

This charm simplifies exposing services running inside a Kubernetes cluster to external clients. It offers TLS termination as well as easy configuration of a number of advanced features including rate limiting, restricting access to specific client IP source ranges, and OWASP ModSecurity Core Rule Set (CRS).

As such, the charm makes it easy for charm developers to provide external access to their HTTP workloads in Kubernetes by easy integration offered via [the charm's `nginx_route` library](https://charmhub.io/nginx-ingress-integrator/libraries/nginx_route).

For DevOps and SRE teams, providing ingress for charms that support a relation to this charm will be possible via a simple `juju relate` command.

```{toctree}
:hidden:
tutorial/index
how-to/index
reference/index
explanation/index
changelog
```
