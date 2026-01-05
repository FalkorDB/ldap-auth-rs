# Secrets Management

## 🔐 Secret Generation with StringSecret

This deployment uses [Kubernetes Secret Generator](https://github.com/mittwald/kubernetes-secret-generator) to automatically generate secure random secrets.

### Installation

```bash
# Install secret generator operator
kubectl apply -f https://github.com/mittwald/kubernetes-secret-generator/releases/latest/download/secret-generator.yaml

# Verify installation
kubectl get deployment -n secret-generator
```

### How It Works

The `StringSecret` CRD automatically generates secure random values:

```yaml
apiVersion: secretgenerator.mittwald.de/v1alpha1
kind: StringSecret
metadata:
  name: ldap-auth-secrets
spec:
  fields:
  - fieldName: API_BEARER_TOKEN
    length: "64"
    encoding: base64
  - fieldName: REDIS_PASSWORD
    length: "32"
    encoding: base64
```

**Benefits:**
- ✅ Auto-generates cryptographically secure secrets
- ✅ Regenerates on deletion (rotation support)
- ✅ Base64 encoded by default
- ✅ Immutable once created (unless deleted)

### Manual Secret Management (Fallback)

If you cannot use StringSecret, uncomment the fallback in [base/secret.yaml](base/secret.yaml):

```bash
# Generate secure secrets manually
export API_BEARER_TOKEN=$(openssl rand -base64 64)
export REDIS_PASSWORD=$(openssl rand -base64 32)

# Create secret
kubectl create secret generic ldap-auth-secrets \
  --from-literal=API_BEARER_TOKEN=$API_BEARER_TOKEN \
  --from-literal=REDIS_PASSWORD=$REDIS_PASSWORD \
  -n ldap-auth-prod
```

### Viewing Generated Secrets

```bash
# View secret (base64 encoded)
kubectl get secret ldap-auth-secrets -n ldap-auth-prod -o yaml

# Decode specific field
kubectl get secret ldap-auth-secrets -n ldap-auth-prod \
  -o jsonpath='{.data.API_BEARER_TOKEN}' | base64 -d
```

### Secret Rotation

```bash
# Delete StringSecret to regenerate
kubectl delete stringsecret ldap-auth-secrets -n ldap-auth-prod

# Wait for regeneration
kubectl wait --for=condition=Ready stringsecret/ldap-auth-secrets -n ldap-auth-prod

# Restart pods to use new secrets
kubectl rollout restart deployment/ldap-auth-rs -n ldap-auth-prod
kubectl rollout restart statefulset/redis -n ldap-auth-prod
```
