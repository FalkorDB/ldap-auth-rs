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
# Generate secure passwords
export ADMIN_PASSWORD=$(openssl rand -base64 32)
export JWT_SECRET=$(openssl rand -base64 64)
export REDIS_PASSWORD=$(openssl rand -base64 32)

# Create secret manually
kubectl create secret generic ldap-auth-secrets \
  --from-literal=ADMIN_USERNAME=admin \
  --from-literal=ADMIN_PASSWORD=$ADMIN_PASSWORD \
  --from-literal=JWT_SECRET=$JWT_SECRET \
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

## 🔄 Scaling

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

# Update ConfigMap with external Redis URL
configMapGenerator:
- name: ldap-auth-config
  behavior: merge
  literals:
  - REDIS_URL=redis://your-redis-host.example.com:6379
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
