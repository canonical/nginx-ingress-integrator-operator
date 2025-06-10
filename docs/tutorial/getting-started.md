
# Quick guide

## What you'll do

- Deploy the `nginx-ingress-integrator` charm
- Relate it to another charm
- Inspect the ingress it creates.

You'll then also look at changing that ingress via a Juju configuration update.

## Requirements

You will need:

* A laptop or desktop running Ubuntu (or you can use a VM).
* [Juju and MicroK8s](https://juju.is/docs/olm/microk8s) installed. Make sure the ingress add-on is enabled by running `microk8s enable ingress`.

## Deploy this charm

To deploy the charm and relate it to
[the Hello Kubecon charm](https://charmhub.io/hello-kubecon) within a Juju Kubernetes model:

    juju deploy nginx-ingress-integrator
    juju deploy hello-kubecon --revision=18 --channel=stable
    juju relate nginx-ingress-integrator hello-kubecon
    # If your cluster has RBAC enabled you'll be prompted to run the following:
    juju trust nginx-ingress-integrator --scope cluster

Once the deployment has completed and the "hello-kubecon" workload state in
`juju status` has changed to "active" you can test the application in
a browser. 

To do so, find the IP address of the ingress controller, which you can do by running `microk8s kubectl get pods -n ingress -o wide`:
```
NAME                                      READY   STATUS    RESTARTS       AGE   IP             NODE        NOMINATED NODE   READINESS GATES
nginx-ingress-microk8s-controller-c4vp9   1/1     Running   2 (119s ago)   17h   10.1.129.161   finistere   <none>           <none>
```
Adding 10.1.129.161 hello-kubecon to /etc/hosts lets you visit http://hello-kubecon and see the hello-kubecon charm in action!

## Inspect the ingress configuration

To inspect the ingress configuration that has been created as a result of these steps, run the following:

    juju run-action nginx-ingress-integrator/0 --wait describe-ingresses

This will return something like the following:

```
unit-nginx-ingress-integrator-0:
  UnitId: nginx-ingress-integrator/0
  id: "2"
  results:
    ingresses: |-
      {'api_version': 'networking.k8s.io/v1',
       'items': [{'api_version': None,
                  'kind': None,
                  'metadata': {'annotations': {'nginx.ingress.kubernetes.io/proxy-body-size': '20m',
                                               'nginx.ingress.kubernetes.io/rewrite-target': '/',
                                               'nginx.ingress.kubernetes.io/ssl-redirect': 'false'},
                               'cluster_name': None,
                               'creation_timestamp': datetime.datetime(2022, 12, 12, 16, 41, 26, tzinfo=tzlocal()),
                               'deletion_grace_period_seconds': None,
                               'deletion_timestamp': None,
                               'finalizers': None,
                               'generate_name': None,
                               'generation': 1,
                               'labels': {'app.juju.is/created-by': 'nginx-ingress-integrator'},
                               'managed_fields': [{'api_version': 'networking.k8s.io/v1',
                                                   'fields_type': 'FieldsV1',
                                                   'fields_v1': {'f:metadata': {'f:annotations': {'.': {},
                                                                                                  'f:nginx.ingress.kubernetes.io/proxy-body-size': {},
                                                                                                  'f:nginx.ingress.kubernetes.io/rewrite-target': {},
                                                                                                  'f:nginx.ingress.kubernetes.io/ssl-redirect': {}}},
                                                                 'f:spec': {'f:ingressClassName': {},
                                                                            'f:rules': {}}},
                                                   'manager': 'OpenAPI-Generator',
                                                   'operation': 'Update',
                                                   'time': datetime.datetime(2022, 12, 12, 16, 41, 26, tzinfo=tzlocal())},
                                                  {'api_version': 'networking.k8s.io/v1',
                                                   'fields_type': 'FieldsV1',
                                                   'fields_v1': {'f:status': {'f:loadBalancer': {'f:ingress': {}}}},
                                                   'manager': 'nginx-ingress-controller',
                                                   'operation': 'Update',
                                                   'time': datetime.datetime(2022, 12, 12, 16, 41, 45, tzinfo=tzlocal())}],
                               'name': 'hello-kubecon-ingress',
                               'namespace': 'ing-test',
                               'owner_references': None,
                               'resource_version': '9123',
                               'self_link': None,
                               'uid': '9dda237a-d903-4031-947d-3a5fd9b4d34e'},
                  'spec': {'default_backend': None,
                           'ingress_class_name': 'public',
                           'rules': [{'host': 'hello-kubecon',
                                      'http': {'paths': [{'backend': {'resource': None,
                                                                      'service': {'name': 'hello-kubecon-service',
                                                                                  'port': {'name': None,
                                                                                           'number': 8080}}},
                                                          'path': '/',
                                                          'path_type': 'Prefix'}]}}],
                           'tls': None},
                  'status': {'load_balancer': {'ingress': [{'hostname': None,
                                                            'ip': '127.0.0.1'}]}}}],
       'kind': 'IngressList',
       'metadata': {'_continue': None,
                    'remaining_item_count': None,
                    'resource_version': '9187',
                    'self_link': None}}
  status: completed
  timing:
    completed: 2022-12-12 16:42:11 +0000 UTC
    enqueued: 2022-12-12 16:42:08 +0000 UTC
    started: 2022-12-12 16:42:11 +0000 UTC
```
This shows a number of things including the name of the [kubernetes service](https://kubernetes.io/docs/concepts/services-networking/service/) for the application (`'service': {'name': 'hello-kubecon-service'`), as well as the port that service is configured with (`8080`). 

You will also see a number of annotations that have been set for the ingress:
```
'metadata': {'annotations': {'nginx.ingress.kubernetes.io/proxy-body-size': '20m',
                             'nginx.ingress.kubernetes.io/rewrite-target': '/',
                             'nginx.ingress.kubernetes.io/ssl-redirect': 'false'},
```
Now let's look at how to change our ingress using Juju configuration.
## Change configuration
In the output above you'll see some default settings for the charm, including `nginx.ingress.kubernetes.io/proxy-body-size': '20m'`. The charm controls this via the [`max-body-size` configuration option](https://charmhub.io/nginx-ingress-integrator/configure#max-body-size). You can easily change this by running:

    juju config nginx-ingress-integrator max-body-size=10

If you re-run the `describe-ingresses` action above, you'll see that the annotation has been updated to `'nginx.ingress.kubernetes.io/proxy-body-size': '10m'`.
