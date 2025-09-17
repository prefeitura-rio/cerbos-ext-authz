# Envoy External Authorization Service for Cerbos

A high-performance external authorization service for Envoy Proxy that integrates with Cerbos PDP (Policy Decision Point). This service validates JWT tokens and performs policy-based authorization decisions using Cerbos.

## Features

- **Policy-based authorization**: Integration with Cerbos Policy Decision Point
- **JWT token validation**: Support for Keycloak and other JWT providers
- **Action mapping**: Dynamic action resolution via mapping service
- **High performance**: HTTP/gRPC-based authorization with caching
- **Resilient**: Circuit breaker pattern with graceful degradation
- **Observable**: Full OpenTelemetry integration with traces, metrics, and logs
- **Configurable**: Environment-based configuration
- **Mock mode**: Development-friendly testing without external dependencies
- **Containerized**: Ready for Kubernetes deployment
- **Safe tracing**: Panic-protected OpenTelemetry integration

## Architecture

```
Client Request → Envoy Proxy → ext_authz Filter → This Service → Cerbos PDP
                                                      ↓           ↑
                                              Cache (Redis)   Mapping Service
                                                      ↓           ↑
                                              Circuit Breaker   JWT Validation
                                                      ↓
                                              OpenTelemetry (SignOz)
```

### Request Flow

1. Client sends request with `Authorization: Bearer <JWT>` header
2. Envoy intercepts and calls this authorization service
3. Service extracts principal and roles from JWT token
4. Service calls mapping service to resolve (service, path, method) → action
5. Service calls Cerbos PDP with principal, resource, and action
6. Returns ALLOW/DENY decision to Envoy
7. Envoy forwards or blocks the request accordingly

## Configuration

The service is configured using environment variables. Copy `.env.example` to `.env` and customize the values for your environment.

### Core Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `CERBOS_CHECK` | Cerbos PDP endpoint URL for authorization checks | `http://cerbos.cerbos.svc.cluster.local:3592/api/check/resources` | No |
| `CERBOS_TIMEOUT_SECONDS` | Timeout for Cerbos API calls (seconds) | `2` | No |
| `MAPPING_SERVICE_URL` | Heimdall mapping service base URL | `http://admin-service.admin.svc.cluster.local:8080` | No |
| `MAPPING_API_TOKEN` | Bearer token for mapping service authentication | - | No |
| `MAPPING_TIMEOUT_MS` | Timeout for mapping service calls (milliseconds) | `500` | No |

### JWT Authentication

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `VERIFY_JWT` | Enable JWT signature verification | `false` | No |
| `KEYCLOAK_JWKS` | JWKS endpoint URL for JWT signature verification | - | **Yes** if `VERIFY_JWT=true` |
| `JWT_TIMEOUT_SECONDS` | Timeout for JWT validation operations | `1` | No |

### Caching & Performance

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `CACHE_TTL_SECONDS` | Cache TTL for successful authorization decisions | `30` | No |
| `CACHE_FAILED_TTL_SECONDS` | Cache TTL for failed authorization decisions | `300` | No |
| `REDIS_URL` | Redis connection URL (falls back to in-memory if not available) | `redis://localhost:6379/0` | No |

### Circuit Breaker & Resilience

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `CIRCUIT_BREAKER_ENABLED` | Enable circuit breaker for Cerbos calls | `true` | No |
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | Number of failures before opening circuit | `5` | No |
| `CIRCUIT_BREAKER_RECOVERY_TIME_SECONDS` | Time before attempting to close circuit | `60` | No |
| `FAILURE_MODE` | Behavior when Cerbos is unavailable (`fail_open` or `fail_closed`) | `fail_open` | No |

### Observability & Monitoring

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OTEL_ENDPOINT` | OpenTelemetry collector endpoint (gRPC) | - | No |
| `OTEL_SERVICE_NAME` | Service name for telemetry | `cerbos-authz` | No |
| `LOG_LEVEL` | Logging level (`debug`, `info`, `warn`, `error`) | `info` | No |
| `HEALTH_CHECK_INTERVAL_SECONDS` | Health check probe interval | `30` | No |

### Development & Testing

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MOCK_MODE` | Enable mock mode (bypasses Cerbos and mapping service) | `false` | No |
| `PORT` | Override HTTP server port | `8000` | No |

### Example Configuration

```bash
CERBOS_CHECK=http://cerbos:3592/api/check/resources
MAPPING_SERVICE_URL=http://admin-service:8080
MAPPING_API_TOKEN=your_mapping_service_token
KEYCLOAK_JWKS=https://keycloak.example.com/auth/realms/your-realm/protocol/openid-connect/certs
VERIFY_JWT=true
CACHE_TTL_SECONDS=30
REDIS_URL=redis://localhost:6379
FAILURE_MODE=fail_open
CIRCUIT_BREAKER_ENABLED=true
OTEL_ENDPOINT=signoz:4317
MOCK_MODE=false
```

### JWT Configuration

The service integrates with Cerbos PDP and supports JWT-based authentication:

1. **Configure JWT verification (optional):**
   ```bash
   # Enable JWT signature verification
   export VERIFY_JWT=true
   export KEYCLOAK_JWKS=https://your-keycloak.example.com/auth/realms/your-realm/protocol/openid-connect/certs
   ```

2. **For development without JWT verification:**
   ```bash
   # Disable JWT verification for testing
   export VERIFY_JWT=false
   ```

3. **Configure Cerbos endpoint:**
   ```bash
   export CERBOS_CHECK=http://cerbos:3592/api/check/resources
   ```

## API Endpoints

### Authorization Endpoint

The service implements the Envoy `ext_authz` filter interface, supporting both HTTP and gRPC protocols.

**HTTP Mode:**
- **Port**: 8000
- **Method**: POST
- **Headers**: `Authorization: Bearer <JWT>` (required)

**gRPC Mode:**
- **Port**: 9000
- **Service**: `envoy.service.auth.v3.Authorization`
- **Method**: `Check`

**Request Headers:**
- `Authorization`: The JWT token for authentication (Bearer format)

**Response:**
- **200 OK**: Request allowed
- **403 Forbidden**: Request denied

**Response Headers:**

**Standard Envoy Headers:**
- `X-Ext-Authz-Check-Result`: `allowed|denied`
- `X-Ext-Authz-Check-Received`: Request details

**Enhanced Cerbos Headers:**
- `X-Cerbos-Status`: Authorization status (`allowed`, `denied`, `invalid_token`, `degraded`, `circuit_breaker_open`)
- `X-Cerbos-Action`: The action that was evaluated
- `X-Cerbos-Cache`: Cache status (`hit` or `miss`)
- `X-Cerbos-Service-Health`: Service health (`healthy` or `degraded`)
- `X-Cerbos-Circuit-Breaker-State`: Circuit breaker state (`closed`, `open`, `half_open`, only when degraded)

## Envoy Configuration

### HTTP Mode

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    http_service:
      server_uri:
        uri: "http://cerbos-authz:8000"
        cluster: "cerbos_authz"
        timeout: 2s
      authorization_request:
        allowed_headers:
          patterns:
          - exact: "authorization"
      authorization_response:
        allowed_upstream_headers:
          patterns:
          - exact: "x-ext-authz-check-result"
          - exact: "x-ext-authz-check-received"
          - exact: "x-cerbos-status"
          - exact: "x-cerbos-action"
          - exact: "x-cerbos-cache"
          - exact: "x-cerbos-service-health"
          - exact: "x-cerbos-circuit-breaker-state"
```

### gRPC Mode

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    grpc_service:
      envoy_grpc:
        cluster_name: "cerbos_authz_grpc"
      timeout: 2s
```

## Development

### Prerequisites

- Go 1.24+
- Docker
- Nix (for development environment)
- Cerbos PDP instance
- JWT identity provider (Keycloak, Auth0, etc.)

### Local Development

1. **Setup with direnv (recommended):**
   ```bash
   # Install direnv if not already installed
   # macOS: brew install direnv
   # Linux: sudo apt install direnv
   
   # Allow direnv in this directory
   direnv allow
   
   # This will automatically load the Nix flake and environment variables
   ```

2. **Setup with Nix (manual):**
   ```bash
   nix develop
   ```

2. **Run locally:**
   ```bash
   just run
   ```

3. **Run in mock mode (for development):**
   ```bash
   just run-mock
   ```
   
   Mock mode bypasses Cerbos and mapping service calls and uses predefined responses for testing.

4. **Run with Docker:**
   ```bash
   just docker-compose
   ```

### Testing

The service can be tested using curl or grpcurl:

**HTTP Mode:**
```bash
curl -X POST http://localhost:8000 \
  -H "Authorization: Bearer your_jwt_token_here" \
  -v
```

**Example Response Headers:**
```
HTTP/1.1 403 Forbidden
X-Ext-Authz-Check-Result: denied
X-Cerbos-Status: denied
X-Cerbos-Cache: miss
X-Cerbos-Service-Health: healthy
Content-Type: text/plain; charset=utf-8

denied by ext_authz: access denied
```

**Test with justfile:**
```bash
just test-curl-http
just test-curl-grpc
```

**gRPC Mode (requires grpcurl):**
```bash
grpcurl -plaintext \
  -d '{"attributes": {"request": {"http": {"headers": {"authorization": "Bearer your_jwt_token_here"}}}}}' \
  localhost:9000 envoy.service.auth.v3.Authorization/Check
```

**Using justfile:**
```bash
just test-curl-http
just test-curl-grpc
```

## Deployment

### Docker

```bash
docker build -t cerbos-authz .
docker run -p 8000:8000 -p 9000:9000 \
  -e CERBOS_CHECK=http://cerbos:3592/api/check/resources \
  -e MAPPING_SERVICE_URL=http://admin-service:8080 \
  -e VERIFY_JWT=true \
  -e KEYCLOAK_JWKS=https://keycloak.example.com/auth/realms/your-realm/protocol/openid-connect/certs \
  cerbos-authz --http=8000 --grpc=9000
```

### Kubernetes

1. **Create secret with service account key:**
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: cerbos-authz-secrets
   type: Opaque
   data:
     jwt-signing-key: <base64-encoded-jwt-public-key>
   ```

2. **Deploy service:**
   ```bash
   kubectl apply -f k8s/
   ```

3. **Scaling Strategy:**
   - **HPA (Horizontal Pod Autoscaler)**: Scales based on CPU/memory usage
   - **VPA (Vertical Pod Autoscaler)**: Optimizes resource requests/limits
   - **PDB (Pod Disruption Budget)**: Ensures availability during scaling
   - **Redis**: Shared cache across all pods for better performance

## Monitoring

### Metrics

Key metrics available:
- `cerbos_requests_total`: Total requests processed
- `cerbos_validation_success_total`: Successful authorizations
- `cerbos_validation_failure_total`: Failed authorizations
- `cerbos_cache_hits_total`: Cache hit rate
- `cerbos_cache_misses_total`: Cache miss rate
- `cerbos_api_duration_seconds`: Cerbos API response time
- `cerbos_circuit_breaker_state`: Circuit breaker status

### Service Health Monitoring

The service provides enhanced visibility into its operational state through response headers:

**Normal Operation:**
```
X-Cerbos-Service-Health: healthy
X-Cerbos-Status: allowed/denied/invalid_token
```

**Service Degradation (fail-open mode):**
```
X-Cerbos-Service-Health: degraded
X-Cerbos-Circuit-Breaker-State: open
X-Cerbos-Status: degraded
```

**Monitoring Recommendations:**
- Alert on `X-Cerbos-Service-Health: degraded`
- Monitor circuit breaker state transitions
- Track cache hit rates for performance optimization
- Use `X-Cerbos-Status` to distinguish between token issues and service problems

### Alerts

Recommended alerts:
- High error rate (>5%)
- Circuit breaker trips
- Cerbos API timeouts
- High response latency (>2s)

## Failure Handling

### Circuit Breaker

The service implements a circuit breaker pattern:
- **Closed**: Normal operation
- **Open**: Stop calling Cerbos API, return degraded responses
- **Half-open**: Test Cerbos API before resuming normal operation

### Graceful Degradation

When Cerbos API is unavailable:
- Return `ALLOW` with `X-Cerbos-Status: degraded`
- Continue serving requests to prevent complete outage
- Monitor and alert on degraded state

## Recent Improvements

### Safe Tracing
- **Panic protection**: OpenTelemetry integration with comprehensive panic recovery
- **Graceful degradation**: Service continues working even if telemetry fails
- **Nil checks**: Robust handling of nil pointers throughout the codebase

### Service Account Authentication
- **Base64 encoding**: Kubernetes-friendly service account key storage
- **Automatic decoding**: Service automatically decodes and uses service account credentials
- **Permission management**: Clear documentation for required IAM roles

### Error Handling
- **Nil pointer protection**: Comprehensive nil checks in Cerbos authorization
- **Circuit breaker safety**: Enhanced circuit breaker with proper state management
- **Graceful failures**: Service handles all error scenarios without panicking

## Security Considerations

- **Secret management**: Use Kubernetes secrets for sensitive data
- **Network security**: Restrict access to authorization service
- **Rate limiting**: Implement at Envoy level
- **Monitoring**: Monitor for abuse and unusual patterns
- **Service account security**: Rotate service account keys regularly

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details. 