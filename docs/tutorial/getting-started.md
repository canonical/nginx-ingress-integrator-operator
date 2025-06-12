
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

Now let's look at how to change our ingress using Juju configuration.
## Change configuration
In the output above you'll see some default settings for the charm, including `nginx.ingress.kubernetes.io/proxy-body-size': '20m'`. The charm controls this via the [`max-body-size` configuration option](https://charmhub.io/nginx-ingress-integrator/configure#max-body-size). You can easily change this by running:

    juju config nginx-ingress-integrator max-body-size=10

If you re-run the `describe-ingresses` action above, you'll see that the annotation has been updated to `'nginx.ingress.kubernetes.io/proxy-body-size': '10m'`.
