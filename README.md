## to use 

# 1 clone or download 
git clone git@github.com:Fern135/jsbg.git

# 2 cd into directory 

# 3 run 
```
npm link
```


```
jsbg new <project-name> [options]

Core:
  --java <17|21|22|23|custom>   Java version (default: 21, for virtual threads)
  --boot <version|latest>       Spring Boot version (default: latest)
  --build <maven|gradle-kts|gradle>  Build tool (default: maven)
  --pack <jar|war>              Packaging (default: jar)
  --rest                        Use Spring MVC (default if nothing chosen)
  --webflux                     Use reactive stack (WebFlux)
  --api-only                    API-only (default)
  --thymeleaf                   Add Thymeleaf sample (email/templates)

Security:
  --security                    Add Spring Security hardening (default on)
  --jwt                         JWT auth (signup/login/me) (default on)
  --sessions                    Add server-side session starter
  --oauth                       Add OAuth2 login stubs (Google/GitHub)
  --cors <origins>              CORS origins (default: * in dev)
  --ratelimit                   In-memory rate-limit (default on)

OpenAPI:
  --openapi                     springdoc-openapi + Swagger UI (default on)
  --apiversion <v1|header|none> API versioning style (default: v1)

Data:
  --sqlite                      Include SQLite driver (default on)
  --psg                         Postgres option available
  --msql                        MySQL/MariaDB option available
  --flyway | --liquibase        DB migrations (choose one)
  --r2dbc                       Reactive DB (R2DBC) option
  --jpa                         Spring Data JPA (Hibernate) option
  --mapstruct                   DTO mapper option
  --paging                      Paging/sorting option (Spring Data)

Infra:
  --redis                       Redis (cache/pubsub) option
  --kafka                       Kafka stub option
  --rabbit                      RabbitMQ stub option
  --es | --opensearch           Search clients option
  --s3                          S3 client stub option
  --mail                        Mail sender + template option

Concurrency/Resilience Demos:
  --demos-io                    Parallel outbound I/O demo
  --demos-cpu                   CPU offload executor demo
  --demos-async                 @Async with virtual threads & fixed pool
  --resilience                  Resilience4j (retry/timeout/circuit breaker)
  --scheduled                   @Scheduled cron demo
  --sse                         Server-Sent Events demo
  --ws                          WebSocket demo
  --grpc                        gRPC starter
  --graphql                     GraphQL starter

Observability:
  --metrics                     Micrometer + Prometheus
  --otel                        OpenTelemetry auto-instrumentation hooks
  --logjson                     Logback JSON + MDC correlation
  --actuator                    Spring Boot Actuator (health/metrics/info)

DevOps:
  -d, --docker                  Add Dockerfile (+ compose via prompts)
  --ngnx                        Offer NGINX reverse proxy (prompt for compose)
  --ci                          GitHub Actions (build/test/docker)
  --port <n>                    HTTP port (default: 8080)

```
