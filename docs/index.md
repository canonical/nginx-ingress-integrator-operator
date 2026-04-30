---
myst:
  html_meta:
    "description lang=en": "Learn how to deploy, configure and operate the NGINX ingress integrator charm using Juju."
---

# NGINX ingress integrator charm

A [Juju](https://juju.is/) [charm](https://documentation.ubuntu.com/juju/3.6/reference/charm/) deploying and managing external access to HTTP/HTTPS services in a Kubernetes cluster through an Nginx Ingress resource. This requires the Kubernetes cluster in question to have an [Nginx Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/) already deployed into it.

This charm simplifies exposing services running inside a Kubernetes cluster to external clients. It offers TLS termination as well as easy configuration of a number of advanced features including rate limiting, restricting access to specific client IP source ranges, and OWASP ModSecurity Core Rule Set (CRS).

As such, the charm makes it easy for charm developers to provide external access to their HTTP workloads in Kubernetes by easy integration offered through [the charm's `nginx_route` library](https://charmhub.io/nginx-ingress-integrator/libraries/nginx_route).

For DevOps and SRE teams, providing ingress for charms that support a relation to this charm will be possible through a simple `juju relate` command.

## In this documentation

| | |
|--|--|
|  [Tutorials](tutorial_index)</br>  Get started - a hands-on introduction to using the NGINX ingress integrator for new users </br> |  [How-to guides](how_to_index) </br> Step-by-step guides covering key operations and common tasks |
| [Reference](reference_index) </br> Technical information - specifications, APIs, architecture | [Explanation](explanation_index) </br> Concepts - discussion and clarification of key topics  |

## Contributing to this documentation

Documentation is an important part of this project, and we take the same open-source approach to the documentation as the code. As such, we welcome community contributions, suggestions, and constructive feedback on our documentation. See [How to contribute](how_to_contribute) for more information.

If there's a particular area of documentation that you'd like to see that's missing, please [file a bug](https://github.com/canonical/nginx-ingress-integrator-operator/issues).

## Project and community

The NGINX ingress integrator charm is a member of the Ubuntu family. It's an open-source project that warmly welcomes community projects, contributions, suggestions, fixes, and constructive feedback.

- [Code of conduct](https://ubuntu.com/community/code-of-conduct)
- [Get support](https://discourse.charmhub.io/)
- [Join our online chat](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
- [Contribute](how_to_contribute)

Thinking about using the NGINX ingress integrator charm for your next project? [Get in touch](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)!

```{toctree}
:hidden:
tutorial/index
how-to/index
reference/index
explanation/index
changelog
```
