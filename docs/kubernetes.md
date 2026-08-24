# Kubernetes Deployment Guide

This guide explains how to deploy **DNS-collector** onto a Kubernetes cluster.

---

## Quick Start

Download the provided [`dnscollector-deployment.yml`](https://github.com/dmachard/DNS-collector/blob/main/dnscollector-deployment.yml) manifest and apply it to your cluster:

```bash
kubectl apply -f https://raw.githubusercontent.com/dmachard/DNS-collector/main/dnscollector-deployment.yml
```

Or apply it locally if you cloned the repository:

```bash
kubectl apply -f dnscollector-deployment.yml
```

Verify that the pod and service are running:

```bash
kubectl get pods -l app=dnscollector
kubectl get svc -l app=dnscollector
```

Check the DNS-collector logs:

```bash
kubectl logs -l app=dnscollector -f
```

---

## What is Deployed

The [`dnscollector-deployment.yml`](https://github.com/dmachard/DNS-collector/blob/main/dnscollector-deployment.yml) manifest defines three core Kubernetes resources:

1. **`ConfigMap` (`dnscollector-config`)**: Contains the DNS-collector YAML configuration (`/etc/dnscollector/config.yml`).
2. **`Service` (`dnscollector-service`)**: Exposes:
   * Port `6000/TCP`: Ingestion port for DNStap collectors.
   * Port `8080/TCP`: Prometheus metrics endpoint.
3. **`Deployment` (`dnscollector-deployment`)**: Runs the `dmachard/dnscollector:latest` container with:
   * Mounted configuration from the ConfigMap.
   * Liveness & Readiness TCP socket probes.
   * Configured resource requests and limits.

---

## Customizing Configuration

You can customize the pipeline (add collectors, transformers, or loggers) directly in the `ConfigMap` section of `dnscollector-deployment.yml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dnscollector-config
  labels:
    app: dnscollector
data:
  config.yml: |
    global:
      trace:
        verbose: true

    multiplexer:
      collectors:
        - name: tap
          dnstap:
            listen-ip: 0.0.0.0
            listen-port: 6000
          transforms:
            normalize:
              qname-lowercase: true
      loggers:
        - name: console
          stdout:
            mode: text
        - name: prom
          prometheus:
            listen-ip: 0.0.0.0
            listen-port: 8080
      routes:
        - from: [ tap ]
          to: [ console, prom ]
```

Apply your updated manifest and trigger a rollout:

```bash
kubectl apply -f dnscollector-deployment.yml
kubectl rollout restart deployment/dnscollector-deployment
```

---

## Connecting DNS Servers (DNStap)

Within your Kubernetes cluster, configure your DNS servers (CoreDNS, Bind9, Unbound, PowerDNS) to stream DNStap logs to:

```text
dnscollector-service.default.svc.cluster.local:6000
```

### Example with Bind9 in Kubernetes:
```text
dnstap {
    all;
};
dnstap-output tcp "dnscollector-service:6000";
```

---

## Scraping Prometheus Metrics

To enable automatic scraping by Prometheus Operator or Prometheus server, add standard annotations to the Deployment template:

```yaml
spec:
  template:
    metadata:
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
```

To test metrics locally with port-forwarding:

```bash
kubectl port-forward svc/dnscollector-service 8080:8080
curl http://localhost:8080/metrics
```

---

## Local Testing with MicroK8s or Minikube

If you do not have a running cluster, you can use [MicroK8s](https://microk8s.io/) or [Minikube](https://minikube.sigs.k8s.io/):

### With MicroK8s:
```bash
# Install MicroK8s
sudo snap install microk8s --classic
sudo microk8s status --wait-ready

# Enable required addons and alias kubectl
sudo microk8s enable dns
sudo snap alias microk8s.kubectl kubectl

# Deploy DNS-collector
kubectl apply -f dnscollector-deployment.yml
```
