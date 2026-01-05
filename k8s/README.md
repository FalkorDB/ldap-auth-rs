# Kubernetes Deployment with Kustomize

This directory contains Kubernetes manifests for deploying the LDAP Auth RS application using Kustomize.

## 📁 Structure

```
k8s/
├── base/                          # Base configurations
│   ├── kustomization.yaml         # Base kustomization
│   ├── namespace.yaml             # Namespace definition
│   ├── configmap.yaml             # Application configuration
│   ├── secret.yaml                # Secrets (passwords, tokens)
│   ├── issuer.yaml                # cert-manager self-signed issuer
│   ├── certificate.yaml           # TLS certificate definition
│   ├── deployment.yaml            # Application deployment
│   ├── service.yaml               # Service definitions
│   ├── hpa.yaml                   # Horizontal Pod Autoscaler
│   ├── redis-deployment.yaml      # Redis StatefulSet
│   ├── redis-service.yaml         # Redis services
│   ├── redis-pvc.yaml             # Redis persistent storage
│   ├── serviceaccount.yaml        # RBAC configuration
│   ├── networkpolicy.yaml         # Network policies
│   ├── poddisruptionbudget.yaml   # PDB for high availability
│   └── servicemonitor.yaml        # Prometheus monitoring
│
└── overlays/                      # Environment-specific configs
    ├── dev/                       # Development environment
    │   ├── kustomization.yaml
    │   ├── deployment-patch.yaml
    │   └── hpa-patch.yaml
    │
    ├── staging/                   # Staging environment
    │   ├── kustomization.yaml
    │   ├── deployment-patch.yaml
    │   └── ingress.yaml
    │
    └── production/                # Production environment
        ├── kustomization.yaml
        ├── deployment-patch.yaml
        ├── hpa-patch.yaml
        ├── redis-patch.yaml
        └── ingress.yaml
```

## 🚀 Quick Start

### Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl CLI tool
- kustomize (v5.0+) or kubectl with built-in kustomize
- [cert-manager](https://cert-manager.io/) (v1.0+) for TLS certificate management

### Install cert-manager

If not already installed:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml

# Verify installation
kubectl get pods -n cert-manager
```

### Deploy to Development

```bash
# Preview what will be deployed
kubectl kustomize k8s/overlays/dev

# Apply to cluster
kubectl apply -k k8s/overlays/dev

# Verify deployment
kubectl get all -n ldap-auth-dev
```

### Deploy to Staging

```bash
kubectl apply -k k8s/overlays/staging
kubectl get all -n ldap-auth-staging
```

### Deploy to Production

```bash
# Review changes before applying
kubectl diff -k k8s/overlays/production

# Apply to production
kubectl apply -k k8s/overlays/production

# Monitor rollout
kubectl rollout status deployment/prod-ldap-auth-rs -n ldap-auth-prod
```

## 🔧 Configuration

### Update Secrets

**IMPORTANT**: Replace default passwords before deploying to production!

```bash
# Generate secure secrets
export API_BEARER_TOKEN=$(openssl rand -base64 64)
export REDIS_PASSWORD=$(openssl rand -base64 32)

# Create secret manually
kubectl create secret generic ldap-auth-secrets \
  --from-literal=API_BEARER_TOKEN=$API_BEARER_TOKEN \
  --from-literal=REDIS_PASSWORD=$REDIS_PASSWORD \
  -n ldap-auth-prod \
  --dry-run=client -o yaml | kubectl apply -f -
```

Or use external secret management tools:
- [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
- [External Secrets Operator](https://external-secrets.io/)
- [HashiCorp Vault](https://www.vaultproject.io/)

### Update ConfigMap

Edit environment-specific configurations in overlay kustomization files:

```yaml
configMapGenerator:
- name: ldap-auth-config
  behavior: merge
  literals:
  - LOG_LEVEL=info
  - CACHE_TTL=300
```

### Update Image Tag

```bash
# Using kustomize edit
cd k8s/overlays/production
kustomize edit set image ldap-auth-rs:v1.2.3

# Or manually edit kustomization.yaml
images:
- name: ldap-auth-rs
  newTag: v1.2.3
```

## 📊 Monitoring & Observability

### Health Checks

```bash
# Check application health
kubectl exec -it deployment/ldap-auth-rs -n ldap-auth-prod -- \
  wget -qO- http://localhost:8080/health

# Check metrics
kubectl port-forward svc/ldap-auth-service 8080:8080 -n ldap-auth-prod
curl http://localhost:8080/metrics
```

### Logs

```bash
# View application logs
kubectl logs -f deployment/ldap-auth-rs -n ldap-auth-prod

# View Redis logs
kubectl logs -f statefulset/redis -n ldap-auth-prod

# Aggregate logs (if Loki/ELK is installed)
kubectl logs -l app.kubernetes.io/name=ldap-auth-rs -n ldap-auth-prod --tail=100
```

### Prometheus Integration

If you have Prometheus Operator installed, the ServiceMonitor will automatically configure scraping:

```bash
# Verify ServiceMonitor
kubectl get servicemonitor -n ldap-auth-prod

# Check Prometheus targets
# Navigate to Prometheus UI → Status → Targets
```

## 🔐 Secrets Management

This deployment uses **StringSecret** for automatic secure secret generation. See [SECRETS_AND_BACKUPS.md](SECRETS_AND_BACKUPS.md) for details.

### Quick Setup

```bash
# Install secret generator
kubectl apply -f https://github.com/mittwald/kubernetes-secret-generator/releases/latest/download/secret-generator.yaml

# Secrets will be auto-generated on first deployment
kubectl apply -k k8s/overlays/production
```

### Manual Secrets (Fallback)

If StringSecret operator is not available, uncomment the fallback Secret in `k8s/base/secret.yaml`.

## 💾 Redis Data Persistence

Redis data is persisted using PersistentVolumes (5Gi in dev, 20Gi in production).

**Persistence Features:**
- StatefulSet with automatic PVC creation
- AOF (Append-Only File) + RDB snapshots enabled
- Data survives pod restarts and rescheduling
- Survives cluster upgrades

**Backup Strategy:**

Use your cloud provider's native backup solutions:

- **AWS**: EBS snapshots, AWS Backup service
- **GCP**: Persistent Disk snapshots, scheduled snapshots
- **Azure**: Disk snapshots, Azure Backup service
- **Redis Native**: SAVE/BGSAVE commands

See [SECRETS_AND_BACKUPS.md](SECRETS_AND_BACKUPS.md) for detailed backup procedures and examples.

## 🌐 Access Patterns

### Internal Access (Default)

This service is designed for **internal cluster use only** and does not expose external LoadBalancers or Ingress by default.

**Access within cluster:**
```bash
# From any pod in the cluster
curl http://ldap-auth-service.ldap-auth-prod.svc.cluster.local:8080/health

# LDAP port
ldapsearch -H ldap://ldap-auth-service.ldap-auth-prod.svc.cluster.local:3389
```

**Local development (port-forward):**
```bash
# Forward to local machine
kubectl port-forward svc/ldap-auth-service 8080:8080 -n ldap-auth-prod
curl http://localhost:8080/health

# CLI tool access
kubectl port-forward svc/ldap-auth-service 8080:8080 -n ldap-auth-prod &
ldap-auth-cli --url http://localhost:8080 user list
```

### External Access (Optional)

**⚠️ WARNING:** Exposing authentication services externally requires additional security:
- Rate limiting / DDoS protection
- IP allowlisting
- mTLS authentication  
- WAF protection
- VPN/Private network access

To enable external access, uncomment Ingress in overlay kustomization:

```bash
# Edit kustomization.yaml
cd k8s/overlays/production
vi kustomization.yaml

# Uncomment:
# resources:
#   - ingress.yaml

# Then edit ingress.yaml and uncomment the manifest
vi ingress.yaml

# Apply
kubectl apply -k k8s/overlays/production
```

## 🔐 Security Best Practices

### Network Policies

Network policies are included to restrict traffic:
- Application can only communicate with Redis and DNS
- Redis can only be accessed by the application
- External ingress is restricted to ingress controller

```bash
# Verify network policies
kubectl get networkpolicy -n ldap-auth-prod
kubectl describe networkpolicy ldap-auth-netpol -n ldap-auth-prod
```

### Security Context

All pods run with:
- Non-root user (UID 1000)
- Read-only root filesystem
- Dropped capabilities
- SeccompProfile (RuntimeDefault)

### RBAC

Minimal RBAC permissions are configured:
- ServiceAccount with limited access
- Role for ConfigMap/Secret read access only

## � TLS Configuration

The deployment includes automated TLS certificate management using cert-manager with self-signed certificates. For production environments, you can switch to Let's Encrypt or your own CA.

### Self-Signed Certificates (Default)

Self-signed certificates are automatically generated and renewed by cert-manager:

```bash
# Verify cert-manager is running
kubectl get pods -n cert-manager

# Check issuer status
kubectl get issuer -n ldap-auth
kubectl describe issuer ldap-auth-selfsigned-issuer -n ldap-auth

# Check certificate status
kubectl get certificate -n ldap-auth
kubectl describe certificate ldap-auth-tls-cert -n ldap-auth

# Verify secret was created
kubectl get secret ldap-auth-tls -n ldap-auth
```

**Certificate Details:**
- **Duration**: 90 days
- **Renewal**: 15 days before expiry (automatic)
- **Algorithm**: RSA 2048-bit
- **Usage**: Server auth + Client auth
- **DNS Names**: 
  - `ldap-auth-service`
  - `ldap-auth-service.ldap-auth`
  - `ldap-auth-service.ldap-auth.svc`
  - `ldap-auth-service.ldap-auth.svc.cluster.local`

### Using Let's Encrypt (Production)

For production with public domains, use Let's Encrypt:

```yaml
# Edit k8s/base/issuer.yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ldap-auth-letsencrypt-issuer
  namespace: ldap-auth
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-private-key
    solvers:
    - http01:
        ingress:
          class: nginx
```

Then update `certificate.yaml` to reference the new issuer:

```yaml
issuerRef:
  name: ldap-auth-letsencrypt-issuer
  kind: Issuer
  group: cert-manager.io
```

### Using Custom CA

For enterprise environments with internal CA:

```bash
# Create CA secret
kubectl create secret tls ca-key-pair \
  --cert=ca.crt \
  --key=ca.key \
  -n ldap-auth

# Update issuer
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ldap-auth-ca-issuer
  namespace: ldap-auth
spec:
  ca:
    secretName: ca-key-pair
EOF
```

### Disabling TLS

To disable TLS (not recommended for production):

```bash
# Edit k8s/base/configmap.yaml
# Set ENABLE_TLS: "false"

# Remove TLS volume mount from k8s/base/deployment.yaml
# Remove issuer.yaml and certificate.yaml from k8s/base/kustomization.yaml
```

### Troubleshooting TLS

```bash
# Check certificate is ready
kubectl get certificate ldap-auth-tls-cert -n ldap-auth
# Should show READY=True

# View certificate details
kubectl describe certificate ldap-auth-tls-cert -n ldap-auth

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Verify TLS secret contents
kubectl get secret ldap-auth-tls -n ldap-auth -o yaml

# Test TLS connection
kubectl run -it --rm debug --image=alpine --restart=Never -- sh
apk add openssl
openssl s_client -connect ldap-auth-service.ldap-auth:8080 -showcerts
```

## �🔄 Scaling

### Manual Scaling

```bash
# Scale application
kubectl scale deployment ldap-auth-rs --replicas=5 -n ldap-auth-prod

# Scale Redis (StatefulSet)
kubectl scale statefulset redis --replicas=3 -n ldap-auth-prod
```

### Horizontal Pod Autoscaler

HPA is configured to auto-scale based on:
- CPU utilization (70% threshold)
- Memory utilization (80% threshold)

```bash
# Check HPA status
kubectl get hpa -n ldap-auth-prod

# View HPA details
kubectl describe hpa ldap-auth-hpa -n ldap-auth-prod
```

## 🗄️ Redis Options

### Option 1: In-Cluster Redis (Default)

Uses StatefulSet with persistent storage (included in base).

**Pros:**
- Simple deployment
- Low latency
- Cost-effective for small/medium workloads

**Cons:**
- Manual backup management
- Limited high availability

### Option 2: Managed Redis

For production, consider using managed Redis:
- AWS ElastiCache
- GCP Memorystore
- Azure Cache for Redis

To use external Redis:

```bash
# Remove Redis from deployment
cd k8s/overlays/production
kustomize edit remove resource ../../base/redis-deployment.yaml
kustomize edit remove resource ../../base/redis-service.yaml

# Update ConfigMap with external Redis connection
configMapGenerator:
- name: ldap-auth-config
  behavior: merge
  literals:
  - REDIS_HOST=your-redis-host.example.com
  - REDIS_PORT=6379
```

### Option 3: Redis Cluster

For high availability, deploy Redis Cluster or Sentinel. Consider using:
- [Redis Operator](https://github.com/spotahome/redis-operator)
- [KubeDB Redis](https://kubedb.com/kubernetes/databases/run-and-manage-redis-on-kubernetes/)

## 🔄 Updates & Rollbacks

### Rolling Updates

```bash
# Update image
kubectl set image deployment/ldap-auth-rs \
  ldap-auth-rs=ldap-auth-rs:v1.2.3 \
  -n ldap-auth-prod

# Watch rollout
kubectl rollout status deployment/ldap-auth-rs -n ldap-auth-prod
```

### Rollback

```bash
# View rollout history
kubectl rollout history deployment/ldap-auth-rs -n ldap-auth-prod

# Rollback to previous version
kubectl rollout undo deployment/ldap-auth-rs -n ldap-auth-prod

# Rollback to specific revision
kubectl rollout undo deployment/ldap-auth-rs --to-revision=2 -n ldap-auth-prod
```

## 🧹 Cleanup

### Remove Specific Environment

```bash
# Development
kubectl delete -k k8s/overlays/dev

# Production
kubectl delete -k k8s/overlays/production
```

### Complete Cleanup

```bash
# Delete all namespaces
kubectl delete namespace ldap-auth-dev
kubectl delete namespace ldap-auth-staging
kubectl delete namespace ldap-auth-prod
```

## 📝 Environment Comparison

| Feature | Dev | Staging | Production |
|---------|-----|---------|------------|
| Replicas | 1 | 2 | 3 |
| HPA Min/Max | 1/3 | 2/10 | 3/20 |
| CPU Request | 50m | 75m | 100m |
| Memory Request | 64Mi | 96Mi | 128Mi |
| Log Level | debug | info | warn |
| Redis Memory | 256MB | 256MB | 1GB |
| Redis Storage | 5Gi | 5Gi | 20Gi |
| Access | ClusterIP | ClusterIP | ClusterIP |
| Ingress | No | No (optional) | No (optional) |
| TLS | N/A | Optional | Optional |
| Anti-Affinity | Preferred | Preferred | Required |

## 🐛 Troubleshooting

### Pod Not Starting

```bash
# Check pod status
kubectl get pods -n ldap-auth-prod

# Describe pod
kubectl describe pod <pod-name> -n ldap-auth-prod

# Check events
kubectl get events -n ldap-auth-prod --sort-by='.lastTimestamp'
```

### Redis Connection Issues

```bash
# Test Redis connectivity from application pod
kubectl exec -it deployment/ldap-auth-rs -n ldap-auth-prod -- sh
# Inside pod:
# nc -zv redis-service 6379

# Check Redis logs
kubectl logs statefulset/redis -n ldap-auth-prod

# Test Redis authentication
kubectl exec -it redis-0 -n ldap-auth-prod -- redis-cli -a $REDIS_PASSWORD ping
```

### HPA Not Scaling

```bash
# Check metrics server
kubectl top nodes
kubectl top pods -n ldap-auth-prod

# If metrics are missing, install metrics-server:
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```

## 📚 Additional Resources

- [Kustomize Documentation](https://kustomize.io/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [12-Factor App Methodology](https://12factor.net/)
- [Production Checklist for Kubernetes](https://kubernetes.io/docs/setup/best-practices/)

## 🤝 Contributing

When making changes to manifests:

1. Test in dev environment first
2. Validate with `kubectl diff -k <overlay>`
3. Apply to staging for integration testing
4. Deploy to production after validation
5. Update this README if adding new features

## 📄 License

This configuration follows the same license as the main application.
