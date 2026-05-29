(how_to_enable_owasp_modsecurity_firewall)=

# How to enable the OWASP ModSecurity web application firewall

[ModSecurity](https://www.modsecurity.org/) is an open-source,
cross-platform web application firewall (WAF) engine for Apache, IIS,
and Nginx that is developed by OWASP. You can enable the ModSecurity
firewall in the Nginx ingress integrator charm using the
`owasp-modsecurity-crs` and `owasp-modsecurity-custom-rules` charm
configuration options.

# Enable OWASP ModSecurity with core rule set

The OWASP ModSecurity Core Rule Set (CRS) is a set of generic attack
detection rules for use with ModSecurity or compatible web application
firewalls. You can enable OWASP ModSecurity and the core rule set by
setting the `owasp-modsecurity-crs` charm configuration to `true`. For
example:

```bash
juju config nginx-ingress-integrator owasp-modsecurity-crs=true
```

# Customize ModSecurity rules

You can also enable additional rules outside the core rule set by
setting the `owasp-modsecurity-custom-rules` charm configuration option.
The `owasp-modsecurity-custom-rules` configuration option will be put in
the `nginx.ingress.kubernetes.io/modsecurity-snippet` Nginx ingress
annotation with other charm-generated configuration snippets.

See the [ModSecurity reference](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29)
manual for the full rule configuration directives.

This option is only effective when `owasp-modsecurity-crs` is set to
`true`.
