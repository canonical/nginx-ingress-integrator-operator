(how_to_enable_owasp_modsecurity_firewall)=

# How to enable the OWASP ModSecurity web application firewall

[ModSecurity](https://www.modsecurity.org/) is an open-source,
cross-platform web application firewall (WAF) engine for Apache, IIS,
and NGINX that is developed by OWASP. You can enable the ModSecurity
firewall in the NGINX ingress integrator charm using the
`owasp-modsecurity-crs` and `owasp-modsecurity-custom-rules` charm
configuration options.

## Enable OWASP ModSecurity with core rule set

The OWASP ModSecurity Core Rule Set (CRS) is a set of generic attack
detection rules for use with ModSecurity or compatible web application
firewalls. Enable OWASP ModSecurity and the core rule set by
setting the `owasp-modsecurity-crs` charm configuration to `true`:

```{bash}
juju config nginx-ingress-integrator owasp-modsecurity-crs=true
```

## Customize ModSecurity rules

Enable additional rules outside the core rule set by
setting the `owasp-modsecurity-custom-rules` charm configuration option.
This configuration option will be put in
the `nginx.ingress.kubernetes.io/modsecurity-snippet` NGINX ingress
annotation with other charm-generated configuration snippets.
Separate each rule using a new line (`\n`).

See the [ModSecurity reference](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29)
manual for the full rule configuration directives.

See the [`owasp-modsecurity-custom-rules` configuration description](https://charmhub.io/nginx-ingress-integrator/configurations#owasp-modsecurity-custom-rules)
for the full configuration format, and here's an example of setting
custom rules using a juju command:

```{bash}
juju config nginx-ingress-integrator owasp-modsecurity-custom-rules="SecAction id:900130,phase:1,nolog,pass,t:none,setvar:tx.crs_exclusions_wordpress=1\n"
```

```{warning}
This option is only effective when `owasp-modsecurity-crs` is set to
`true`.
```
