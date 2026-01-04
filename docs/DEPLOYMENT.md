# Deployment Guide

## Deployment Options

### 1. Docker (Recommended)

#### Single Container

```bash
# Build the image
docker build -t ldap-auth-rs:latest .

# Run with environment variables
docker run -d \
  --name ldap-auth \
  -p 8080:8080 \
  -p 3893:3893 \
  -e API_BEARER_TOKEN="your-secure-token" \
  -e REDIS_URL="redis://redis-host:6379" \
  -e RUST_LOG="info" \
  --restart unless-stopped \
  ldap-auth-rs:latest
```

#### Docker Compose (Full Stack)

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped

  ldap-auth:
    build: .
    ports:
      - "8080:8080"
      - "3893:3893"
    environment:
      API_BEARER_TOKEN: ${API_BEARER_TOKEN}
      REDIS_URL: redis://redis:6379
      RUST_LOG: info
    depends_on:
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  redis-data:
```

Start the stack:
```bash
docker-compose up -d
```

### 2. Kubernetes

#### Deployment Manifest

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ldap-auth
---
apiVersion: v1
kind: Secret
metadata:
  name: ldap-auth-secrets
  namespace: ldap-auth
type: Opaque
stringData:
  API_BEARER_TOKEN: your-secure-token-here
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ldap-auth-config
  namespace: ldap-auth
data:
  REDIS_URL: "redis://redis-service:6379"
  RUST_LOG: "info"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ldap-auth
  namespace: ldap-auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ldap-auth
  template:
    metadata:
      labels:
        app: ldap-auth
    spec:
      containers:
      - name: ldap-auth
        image: ldap-auth-rs:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 3893
          name: ldap
        env:
        - name: API_BEARER_TOKEN
          valueFrom:
            secretKeyRef:
              name: ldap-auth-secrets
              key: API_BEARER_TOKEN
        - name: REDIS_URL
          valueFrom:
            configMapKeyRef:
              name: ldap-auth-config
              key: REDIS_URL
        - name: RUST_LOG
          valueFrom:
            configMapKeyRef:
              name: ldap-auth-config
              key: RUST_LOG
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: ldap-auth-service
  namespace: ldap-auth
spec:
  selector:
    app: ldap-auth
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: ldap
    port: 3893
    targetPort: 3893
---
apiVersion: v1
kind: Service
metadata:
  name: redis-service
  namespace: ldap-auth
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: ldap-auth
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-data
          mountPath: /data
      volumes:
      - name: redis-data
        persistentVolumeClaim:
          claimName: redis-pvc
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
  namespace: ldap-auth
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 20Gi
```

Deploy:
```bash
kubectl apply -f k8s/deployment.yaml
```

#### Ingress (Optional)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ldap-auth-ingress
  namespace: ldap-auth
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - ldap-auth.example.com
    secretName: ldap-auth-tls
  rules:
  - host: ldap-auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ldap-auth-service
            port:
              number: 8080
```

### 3. Helm Chart

#### values.yaml

```yaml
replicaCount: 3

image:
  repository: ldap-auth-rs
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  http:
    port: 8080
  ldap:
    port: 3893

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: ldap-auth.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: ldap-auth-tls
      hosts:
        - ldap-auth.example.com

resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 64Mi

redis:
  enabled: true
  auth:
    enabled: true
    password: secure-redis-password
  master:
    persistence:
      enabled: true
      size: 5Gi

config:
  bearerToken: ""  # Set via --set or secrets
  redisUrl: "redis://:password@redis-master:6379"
  logLevel: "info"

metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
```

Install:
```bash
helm install ldap-auth ./helm/ldap-auth \
  --set config.bearerToken="your-secure-token" \
  --namespace ldap-auth \
  --create-namespace
```

### 4. Systemd Service

For bare metal or VM deployment:

```ini
[Unit]
Description=LDAP Auth RS Service
After=network.target redis.service
Wants=redis.service

[Service]
Type=simple
User=ldap-auth
Group=ldap-auth
WorkingDirectory=/opt/ldap-auth-rs
Environment="API_BEARER_TOKEN=your-token"
Environment="REDIS_URL=redis://127.0.0.1:6379"
Environment="RUST_LOG=info"
ExecStart=/opt/ldap-auth-rs/ldap-auth-rs
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/ldap-auth

[Install]
WantedBy=multi-user.target
```

Setup:
```bash
# Create user
sudo useradd -r -s /bin/false ldap-auth

# Copy binary
sudo cp target/release/ldap-auth-rs /opt/ldap-auth-rs/

# Install service
sudo cp ldap-auth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ldap-auth
sudo systemctl start ldap-auth
```

## Monitoring Setup

### Prometheus

```yaml
scrape_configs:
  - job_name: 'ldap-auth'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - ldap-auth
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: ldap-auth
        action: keep
      - source_labels: [__address__]
        target_label: __address__
        regex: ([^:]+)(?::\d+)?
        replacement: $1:8080
    metrics_path: '/metrics'
```

### Grafana Dashboard

Import the dashboard from [METRICS.md](../METRICS.md) or use this query:

```promql
# Request rate
rate(http_requests_total[5m])

# Error rate
rate(http_requests_total{status=~"5.."}[5m])

# Latency p95
histogram_quantile(0.95, rate(http_requests_duration_seconds_bucket[5m]))
```

### ELK Stack Integration

Forward logs to Elasticsearch:

```yaml
filebeat.inputs:
- type: container
  paths:
    - '/var/lib/docker/containers/*/*.log'
  processors:
    - add_kubernetes_metadata:
        host: ${NODE_NAME}
        matchers:
        - logs_path:
            logs_path: "/var/lib/docker/containers/"

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "ldap-auth-%{+yyyy.MM.dd}"
```

## High Availability

### Redis Sentinel

For Redis HA:

```yaml
services:
  redis-master:
    image: redis:7-alpine
    command: redis-server --appendonly yes

  redis-replica:
    image: redis:7-alpine
    command: redis-server --slaveof redis-master 6379 --appendonly yes
    depends_on:
      - redis-master

  redis-sentinel:
    image: redis:7-alpine
    command: redis-sentinel /etc/redis/sentinel.conf
    depends_on:
      - redis-master
      - redis-replica
```

Update connection string:
```bash
REDIS_URL="redis-sentinel://sentinel1,sentinel2,sentinel3/mymaster"
```

### Load Balancing

Use a load balancer (nginx, HAProxy, or cloud LB):

```nginx
upstream ldap_auth {
    least_conn;
    server ldap-auth-1:8080;
    server ldap-auth-2:8080;
    server ldap-auth-3:8080;
}

server {
    listen 80;
    server_name ldap-auth.example.com;

    location / {
        proxy_pass http://ldap_auth;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /health {
        proxy_pass http://ldap_auth;
        access_log off;
    }
}
```

## Scaling Guidelines

### Horizontal Scaling

The application is stateless and can be scaled horizontally:

```bash
# Docker Compose
docker-compose up -d --scale ldap-auth=5

# Kubernetes
kubectl scale deployment ldap-auth -n ldap-auth --replicas=5

# Verify
kubectl get pods -n ldap-auth
```

### Resource Requirements

| Environment | vCPU | Memory | Instances |
|-------------|------|--------|-----------|
| Development | 0.5  | 128MB  | 1         |
| Staging     | 1    | 256MB  | 2         |
| Production  | 2    | 512MB  | 3+        |

### Performance Tuning

- **Connection Pool**: Adjust in `src/redis_db.rs` based on load
- **Token Cache**: Increase size for high auth volumes
- **Log Level**: Use `warn` or `error` in production
- **Metrics Scraping**: 15-30s intervals recommended

## Security Hardening

### Network Policies (Kubernetes)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ldap-auth-policy
  namespace: ldap-auth
spec:
  podSelector:
    matchLabels:
      app: ldap-auth
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
```

### TLS/SSL

Always use TLS in production:

```bash
# Mount certificates in Docker
docker run -d \
  -v /etc/ssl/certs:/certs:ro \
  -e TLS_CERT_PATH=/certs/server.crt \
  -e TLS_KEY_PATH=/certs/server.key \
  ldap-auth-rs:latest

# Kubernetes secret
kubectl create secret tls ldap-auth-tls \
  --cert=server.crt \
  --key=server.key \
  -n ldap-auth
```

## Backup & Recovery

### Redis Backup

```bash
# RDB snapshot (Docker)
docker exec redis redis-cli BGSAVE

# Copy snapshot
docker cp redis:/data/dump.rdb ./backup/

# Restore
docker cp ./backup/dump.rdb redis:/data/
docker restart redis
```

### Kubernetes Backup

```bash
# Backup secrets and configs
kubectl get secret,configmap -n ldap-auth -o yaml > backup.yaml

# Backup persistent data
kubectl exec redis-0 -n ldap-auth -- redis-cli BGSAVE
kubectl cp ldap-auth/redis-0:/data/dump.rdb ./redis-backup.rdb
```

## Troubleshooting

### Check Logs

```bash
# Docker
docker logs ldap-auth

# Kubernetes
kubectl logs -f deployment/ldap-auth -n ldap-auth

# Systemd
sudo journalctl -u ldap-auth -f
```

### Health Check

```bash
# HTTP health endpoint
curl http://localhost:8080/health

# Expected response
{"status":"healthy","redis":"connected","timestamp":"2026-01-04T..."}
```

### Common Issues

1. **Redis connection failed**
   - Check `REDIS_URL` configuration
   - Verify Redis is running
   - Check network connectivity

2. **Bearer token authentication failed**
   - Verify `API_BEARER_TOKEN` is set
   - Check token in request header
   - Ensure token matches exactly

3. **High memory usage**
   - Check token cache size
   - Review connection pool settings
   - Monitor Redis memory usage
