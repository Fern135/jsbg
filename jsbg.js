#!/usr/bin/env node
/**
 * JSBG — Java Spring Boot Generator (fixed)
 * - Sanitizes Java package name from project name
 * - Adds spring-boot-starter-jdbc for DBs
 * - Writes spring.jpa config ONLY when --jpa
 * - If --jpa: generates User entity + UserRepository and Auth uses JPA
 */

const fs = require("fs");
const path = require("path");
const readline = require("readline");

// ---------- helpers ----------
const log = console.log;
const err = console.error;
const die = (m) => { err(m); process.exit(1); };
const mkdirp = (p) => fs.mkdirSync(p, { recursive: true });
const write = (p, s) => (mkdirp(path.dirname(p)), fs.writeFileSync(p, s, "utf8"));
const yn = (q) => prompt(`${q} (y/N): `).then(a => /^y(es)?$/i.test(a.trim()));

function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(res => rl.question(question, ans => (rl.close(), res(ans))));
}

// Artifact stays as-is; package must be safe
function toArtifactId(name) { return String(name).trim(); }
function toPackageName(name) {
  const base = String(name).trim().toLowerCase().replace(/[^a-z0-9]+/g, "_");
  const safe = /^[a-z]/.test(base) ? base : `app_${base}`;
  return `com.example.${safe}`;
}
function toPackagePath(pkg) { return pkg.replace(/\./g, "/"); }

function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 2; i < argv.length; i++) {
    const x = argv[i];
    if (x === "-h" || x === "--help") a.help = true;
    else if (x === "new") a.cmd = "new";
    else if (!a.name && a.cmd === "new" && !x.startsWith("-")) a.name = x;
    else if (x === "-d" || x === "--docker") a.docker = true;
    else if (x === "--java") a.java = argv[++i];
    else if (x === "--boot") a.boot = argv[++i];
    else if (x === "--build") a.build = argv[++i];
    else if (x === "--pack") a.pack = argv[++i];
    else if (x === "--rest") a.rest = true;
    else if (x === "--webflux") a.webflux = true;
    else if (x === "--api-only") a.apiOnly = true;
    else if (x === "--thymeleaf") a.thymeleaf = true;
    else if (x === "--security") a.security = true;
    else if (x === "--jwt") a.jwt = true;
    else if (x === "--sessions") a.sessions = true;
    else if (x === "--oauth") a.oauth = true;
    else if (x === "--cors") a.cors = argv[++i];
    else if (x === "--ratelimit") a.ratelimit = true;
    else if (x === "--openapi") a.openapi = true;
    else if (x === "--apiversion") a.apiversion = argv[++i];
    else if (x === "--sqlite") a.sqlite = true;
    else if (x === "--psg") a.psg = true;
    else if (x === "--msql") a.msql = true;
    else if (x === "--flyway") a.flyway = true;
    else if (x === "--liquibase") a.liquibase = true;
    else if (x === "--r2dbc") a.r2dbc = true;
    else if (x === "--jpa") a.jpa = true;
    else if (x === "--mapstruct") a.mapstruct = true;
    else if (x === "--paging") a.paging = true;
    else if (x === "--redis") a.redis = true;
    else if (x === "--kafka") a.kafka = true;
    else if (x === "--rabbit") a.rabbit = true;
    else if (x === "--es") a.es = true;
    else if (x === "--opensearch") a.opensearch = true;
    else if (x === "--s3") a.s3 = true;
    else if (x === "--mail") a.mail = true;
    else if (x === "--demos-io") a.demosIO = true;
    else if (x === "--demos-cpu") a.demosCPU = true;
    else if (x === "--demos-async") a.demosAsync = true;
    else if (x === "--resilience") a.resilience = true;
    else if (x === "--scheduled") a.scheduled = true;
    else if (x === "--sse") a.sse = true;
    else if (x === "--ws") a.ws = true;
    else if (x === "--grpc") a.grpc = true;
    else if (x === "--graphql") a.graphql = true;
    else if (x === "--metrics") a.metrics = true;
    else if (x === "--otel") a.otel = true;
    else if (x === "--logjson") a.logjson = true;
    else if (x === "--actuator") a.actuator = true;
    else if (x === "--ngnx") a.nginx = true;
    else if (x === "--ci") a.ci = true;
    else if (x === "--port") a.port = Number(argv[++i]);
    else if (x.startsWith("-")) die(`Unknown option: ${x}`);
    else a._.push(x);
  }
  return a;
}

// ---------- defaults ----------
const DEFAULTS = {
  java: "21",
  boot: "latest",
  build: "maven",
  pack: "jar",
  rest: true,
  apiOnly: true,
  security: true,
  jwt: true,
  openapi: true,
  ratelimit: true,
  sqlite: true,
  apiversion: "v1",
  port: 8080
};

function usage() {
  log(`Usage:
  jsbg new <project-name> [options]
  -d, --docker                  Add Dockerfile (compose via prompts)
  --java <17|21|22|23|custom>   Java (default: 21)
  --boot <ver|latest>           Spring Boot (default: latest)
  --build <maven|gradle-kts|gradle> (default: maven)
  --pack <jar|war>              (default: jar)
  --rest | --webflux            API style (default: --rest)
  --api-only | --thymeleaf
  --security 
  --jwt 
  --sessions 
  --oauth 
  --cors "*" 
  --ratelimit
  --openapi 
  --apiversion <v1|header|none>
  --sqlite 
  --psg 
  --msql 
  --flyway 
  --liquibase 
  --r2dbc 
  --jpa 
  --mapstruct 
  --paging
  --redis 
  --kafka 
  --rabbit 
  --es 
  --opensearch 
  --s3 
  --mail
  --demos-io 
  --demos-cpu 
  --demos-async 
  --resilience 
  --scheduled 
  --sse 
  --ws 
  --grpc 
  --graphql
  --metrics 
  --otel 
  --logjson 
  --actuator
  --ngnx 
  --ci 
  --port <n>
`);
}

// ---------- templates ----------
function pomXml(opts) {
  const deps = [];
  const anyDb = opts.sqlite || opts.psg || opts.msql || opts.r2dbc || opts.jpa;

  // API
  if (opts.rest) deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>`);
  if (opts.webflux) deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-webflux</artifactId></dependency>`);

  // Security
  if (opts.security) deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>`);
  if (opts.jwt) {
    deps.push(`<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId><version>0.11.5</version></dependency>`);
    deps.push(`<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-impl</artifactId><version>0.11.5</version><scope>runtime</scope></dependency>`);
    deps.push(`<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-jackson</artifactId><version>0.11.5</version><scope>runtime</scope></dependency>`);
  }
  deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-validation</artifactId></dependency>`);

  // Data / JDBC / JPA
  if (anyDb && !opts.r2dbc) deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-jdbc</artifactId></dependency>`);
  if (opts.jpa) deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>`);
  if (opts.sqlite) deps.push(`<dependency><groupId>org.xerial</groupId><artifactId>sqlite-jdbc</artifactId><version>3.46.0.0</version></dependency>`);
  if (opts.psg) deps.push(`<dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId><scope>runtime</scope></dependency>`);
  if (opts.msql) deps.push(`<dependency><groupId>com.mysql</groupId><artifactId>mysql-connector-j</artifactId><scope>runtime</scope></dependency>`);
  if (opts.r2dbc) deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-r2dbc</artifactId></dependency>`);

  // Migrations
  if (opts.flyway) deps.push(`<dependency><groupId>org.flywaydb</groupId><artifactId>flyway-core</artifactId></dependency>`);
  if (opts.liquibase) deps.push(`<dependency><groupId>org.liquibase</groupId><artifactId>liquibase-core</artifactId></dependency>`);

  // Optional libs (trimmed for brevity—add as needed)
  if (opts.openapi) deps.push(`<dependency><groupId>org.springdoc</groupId><artifactId>springdoc-openapi-starter-webmvc-ui</artifactId><version>2.6.0</version></dependency>`);
  if (opts.redis) deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-redis</artifactId></dependency>`);
  if (opts.mail || opts.thymeleaf) {
    deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-mail</artifactId></dependency>`);
    deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-thymeleaf</artifactId></dependency>`);
  }

  // Test
  deps.push(`<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-test</artifactId><scope>test</scope></dependency>`);

  const packaging = opts.pack || "jar";
  const javaVersion = opts.java || "21";
  return `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0  http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>${opts.groupId}</groupId>
  <artifactId>${opts.artifactId}</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <name>${opts.artifactId}</name>
  <description>Generated by JSBG</description>
  <packaging>${packaging}</packaging>

  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>${opts.boot === "latest" ? "3.3.3" : opts.boot}</version>
    <relativePath/>
  </parent>

  <properties>
    <java.version>${javaVersion}</java.version>
  </properties>

  <dependencies>
    ${deps.join("\n    ")}
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
        <configuration>
          <image><name>${opts.artifactId}:latest</name></image>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>`;
}

function appYml(opts) {
  const port = opts.port;
  const cors = opts.cors || "*";
  const jpaBlock = opts.jpa ? `
  jpa:
    hibernate:
      ddl-auto: update   # demo convenience; prefer Flyway/Liquibase in prod
    show-sql: false` : ``;

  const sqliteBlock = opts.sqlite ? `
  datasource:
    url: jdbc:sqlite:./data/app.db
    driver-class-name: org.sqlite.JDBC` : `
  # datasource configured via env (POSTGRES/MySQL) or profiles`;

  return `server:
  port: ${port}
spring:
  application:
    name: ${opts.artifactId}${sqliteBlock}${jpaBlock}
  thymeleaf:
    check-template-location: ${opts.thymeleaf ? "true" : "false"}

app:
  security:
    jwt:
      secret: "\${JWT_SECRET:change-me}"
      expires-minutes: 60
  cors:
    allowed-origins: "${cors}"

management:
  endpoints:
    web:
      exposure:
        include: ${opts.actuator ? '"health,info,metrics,prometheus"' : '"health,info"'}
`;
}

function applicationJava(opts) {
  return `package ${opts.packageName};

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }
}
`;
}

function controllerJava(opts) {
  const base = opts.apiversion === "header" ? "" : "/api/" + (opts.apiversion || "v1");
  return `package ${opts.packageName}.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.time.Instant;
import java.util.Map;

@RestController
public class MetaController {
  @GetMapping("${base}/health")
  public Map<String, Object> health() {
    return Map.of("status", "ok", "time", Instant.now().toString());
  }

  @GetMapping("${base}/ready")
  public Map<String, Object> ready() {
    return Map.of("ready", true);
  }
}
`;
}

function securityJava(opts) {
  const base = opts.apiversion === "header" ? "/api" : "/api/" + (opts.apiversion || "v1");
  return `package ${opts.packageName}.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .csrf(csrf -> csrf.disable()) // stateless API (JWT)
      .headers(h -> h
        .xssProtection(Customizer.withDefaults())
        .contentTypeOptions(Customizer.withDefaults())
        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
      )
      .authorizeHttpRequests(auth -> auth
        .requestMatchers(HttpMethod.GET, "${base}/health", "${base}/ready").permitAll()
        .requestMatchers("${base}/auth/**").permitAll()
        .anyRequest().authenticated()
      );
    return http.build();
  }
}
`;
}

function jwtJava(opts) {
  return `package ${opts.packageName}.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Component
public class JwtService {
  private final Key key;
  private final long ttlMinutes;

  public JwtService(
    @Value("\${app.security.jwt.secret}") String secret,
    @Value("\${app.security.jwt.expires-minutes}") long ttlMinutes
  ) {
    this.key = Keys.hmacShaKeyFor(secret.getBytes());
    this.ttlMinutes = ttlMinutes;
  }

  public String issue(String sub, Map<String, Object> claims) {
    Instant now = Instant.now();
    return Jwts.builder()
      .setSubject(sub)
      .addClaims(claims)
      .setIssuedAt(Date.from(now))
      .setNotBefore(Date.from(now))
      .setExpiration(Date.from(now.plusSeconds(ttlMinutes * 60)))
      .signWith(key, SignatureAlgorithm.HS256)
      .compact();
  }

  public Jws<Claims> parse(String token) {
    return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
  }
}
`;
}

// --- JPA model & repository (only when --jpa) ---
function userEntityJava(opts) {
  return `package ${opts.packageName}.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "users", indexes = { @Index(name="uk_users_email", columnList="email", unique=true) })
public class User {
  @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable=false, unique=true)
  private String email;

  @Column(nullable=false)
  private String passwordHash;

  @Column(nullable=false)
  private Instant createdAt = Instant.now();

  public Long getId(){ return id; }
  public void setId(Long id){ this.id = id; }

  public String getEmail(){ return email; }
  public void setEmail(String email){ this.email = email; }

  public String getPasswordHash(){ return passwordHash; }
  public void setPasswordHash(String passwordHash){ this.passwordHash = passwordHash; }

  public Instant getCreatedAt(){ return createdAt; }
  public void setCreatedAt(Instant createdAt){ this.createdAt = createdAt; }
}
`;
}

function userRepoJava(opts) {
  return `package ${opts.packageName}.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByEmail(String email);
}
`;
}

function authControllerJava_inMemory(opts) {
  const base = opts.apiversion === "header" ? "/api" : "/api/" + (opts.apiversion || "v1");
  return `package ${opts.packageName}.web;

import ${opts.packageName}.security.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("${base}/auth")
public class AuthController {

  private final JwtService jwt;
  public AuthController(JwtService jwt){ this.jwt = jwt; }

  static class User { String email; String hash; Instant created = Instant.now(); }
  static final Map<String, User> USERS = new ConcurrentHashMap<>();

  record AuthReq(String email, String password){}
  record Profile(String email, String createdAt){}
  record Token(String access_token, String token_type, long expires_minutes){}

  @PostMapping("/signup")
  public Object signup(@RequestBody AuthReq req) {
    if (USERS.containsKey(req.email())) {
      return Map.of("status", 409, "detail", "Email already registered");
    }
    User u = new User();
    u.email = req.email();
    u.hash = BCrypt.hashpw(req.password(), BCrypt.gensalt());
    USERS.put(u.email, u);
    return new Profile(u.email, u.created.toString());
  }

  @PostMapping("/login")
  public Object login(@RequestBody AuthReq req) {
    User u = USERS.get(req.email());
    if (u == null || !BCrypt.checkpw(req.password(), u.hash)) {
      return Map.of("status", 401, "detail", "Invalid credentials");
    }
    String token = jwt.issue(u.email, Map.of("role","user"));
    return new Token(token, "bearer", 60);
  }

  @GetMapping("/me")
  public Object me(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
    if (authHeader == null || !authHeader.toLowerCase().startsWith("bearer ")) {
      return Map.of("status", 401, "detail", "Missing bearer token");
    }
    var token = authHeader.substring(7);
    var jws = jwt.parse(token);
    String sub = jws.getBody().getSubject();
    var u = USERS.get(sub);
    if (u == null) return Map.of("status", 401, "detail", "User not found");
    return new Profile(u.email, u.created.toString());
  }
}
`;
}

function authControllerJava_jpa(opts) {
  const base = opts.apiversion === "header" ? "/api" : "/api/" + (opts.apiversion || "v1");
  return `package ${opts.packageName}.web;

import ${opts.packageName}.domain.User;
import ${opts.packageName}.domain.UserRepository;
import ${opts.packageName}.security.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("${base}/auth")
public class AuthController {

  private final JwtService jwt;
  private final UserRepository repo;

  public AuthController(JwtService jwt, UserRepository repo){
    this.jwt = jwt; this.repo = repo;
  }

  record AuthReq(String email, String password){}
  record Profile(String email, String createdAt){}
  record Token(String access_token, String token_type, long expires_minutes){}

  @PostMapping("/signup")
  public Object signup(@RequestBody AuthReq req) {
    if (repo.findByEmail(req.email()).isPresent()) {
      return Map.of("status", 409, "detail", "Email already registered");
    }
    User u = new User();
    u.setEmail(req.email());
    u.setPasswordHash(BCrypt.hashpw(req.password(), BCrypt.gensalt()));
    repo.save(u);
    return new Profile(u.getEmail(), u.getCreatedAt().toString());
  }

  @PostMapping("/login")
  public Object login(@RequestBody AuthReq req) {
    var u = repo.findByEmail(req.email()).orElse(null);
    if (u == null || !BCrypt.checkpw(req.password(), u.getPasswordHash())) {
      return Map.of("status", 401, "detail", "Invalid credentials");
    }
    String token = jwt.issue(u.getEmail(), Map.of("role","user"));
    return new Token(token, "bearer", 60);
  }

  @GetMapping("/me")
  public Object me(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
    if (authHeader == null || !authHeader.toLowerCase().startsWith("bearer ")) {
      return Map.of("status", 401, "detail", "Missing bearer token");
    }
    var token = authHeader.substring(7);
    var jws = jwt.parse(token);
    String email = jws.getBody().getSubject();
    var u = repo.findByEmail(email).orElse(null);
    if (u == null) return Map.of("status", 401, "detail", "User not found");
    return new Profile(u.getEmail(), u.getCreatedAt().toString());
  }
}
`;
}

function dockerfile(opts) {
  const java = opts.java || "21";
  return `FROM eclipse-temurin:${java}-jre-alpine
WORKDIR /app
COPY target/${opts.artifactId}-0.0.1-SNAPSHOT.jar app.jar
RUN adduser -D appuser
USER appuser
EXPOSE ${opts.port}
ENTRYPOINT ["java","-jar","/app/app.jar"]
`;
}

function composeYaml(opts, includeApi, includePostgres, includeMySQL, includeRedis, includeNginx) {
  const port = opts.port;
  const lines = [];
  lines.push(`services:`);
  if (includeApi) {
    lines.push(`  api:`);
    lines.push(`    build: .`);
    lines.push(`    image: ${opts.artifactId}:latest`);
    lines.push(`    environment:`);
    lines.push(`      JWT_SECRET: "change-me"`);
    if (includePostgres) lines.push(`      SPRING_DATASOURCE_URL: "jdbc:postgresql://postgres:5432/app"`);
    if (includeMySQL)    lines.push(`      SPRING_DATASOURCE_URL: "jdbc:mysql://mysql:3306/app"`);
    lines.push(`    ports: ["${port}:${port}"]`);
    const deps = [ includePostgres && "postgres", includeMySQL && "mysql", includeRedis && "redis", includeNginx && "proxy" ].filter(Boolean);
    if (deps.length) lines.push(`    depends_on: [${deps.join(", ")}]`);
  }
  if (includePostgres) {
    lines.push(`  postgres:`);
    lines.push(`    image: postgres:16`);
    lines.push(`    environment: { POSTGRES_DB: app, POSTGRES_USER: user, POSTGRES_PASSWORD: pass }`);
    lines.push(`    ports: ["5432:5432"]`);
    lines.push(`    volumes: ["pgdata:/var/lib/postgresql/data"]`);
  }
  if (includeMySQL) {
    lines.push(`  mysql:`);
    lines.push(`    image: mysql:8`);
    lines.push(`    environment: { MYSQL_DATABASE: app, MYSQL_USER: user, MYSQL_PASSWORD: pass, MYSQL_ROOT_PASSWORD: root }`);
    lines.push(`    command: --default-authentication-plugin=mysql_native_password`);
    lines.push(`    ports: ["3306:3306"]`);
    lines.push(`    volumes: ["mysqldata:/var/lib/mysql"]`);
  }
  if (includeRedis) {
    lines.push(`  redis:`);
    lines.push(`    image: redis:7`);
    lines.push(`    ports: ["6379:6379"]`);
  }
  if (includeNginx) {
    lines.push(`  proxy:`);
    lines.push(`    image: nginx:stable`);
    lines.push(`    volumes: ["./nginx.conf:/etc/nginx/nginx.conf:ro"]`);
    lines.push(`    ports: ["80:80"]`);
    lines.push(`    depends_on: [api]`);
  }
  if (includePostgres) lines.push(`volumes:\n  pgdata: {}`);
  if (includeMySQL)   lines.push(includePostgres ? `  mysqldata: {}` : `volumes:\n  mysqldata: {}`);
  return lines.join("\n") + "\n";
}

function nginxConf(opts) {
  const port = opts.port;
  return `events { worker_connections 4096; }
http {
  server {
    listen 80;
    location / { proxy_pass http://api:${port}; proxy_set_header Host $host; proxy_http_version 1.1; }
  }
}`;
}

function readmeMd(opts) {
  return `# ${opts.artifactId}
Generated by **JSBG** — Java Spring Boot Generator.

## Stack
- Java ${opts.java}, Spring Boot ${opts.boot === "latest" ? "3.3.x" : opts.boot}, Maven
- API style: ${opts.webflux ? "WebFlux (reactive)" : "REST (Spring MVC)"}; versioning: ${opts.apiversion}
- Security: Spring Security ${opts.jwt ? "+ JWT" : ""}

## Run (dev)
# Set a strong JWT secret
export JWT_SECRET=$(openssl rand -hex 32)

# Build & run
mvn -q -DskipTests package
java -jar target/${opts.artifactId}-0.0.1-SNAPSHOT.jar

# Or run directly:
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-DJWT_SECRET=$JWT_SECRET"

## Endpoints
- GET /api/${opts.apiversion}/health
- GET /api/${opts.apiversion}/ready
- POST /api/${opts.apiversion}/auth/signup
- POST /api/${opts.apiversion}/auth/login
- GET  /api/${opts.apiversion}/auth/me

## Notes
- Default DB is SQLite (good for dev). For production, prefer Postgres/MySQL.
- If you pass --jpa, a User entity + repository are generated.
`;
}

// ---------- main ----------
async function main() {
  const args = parseArgs(process.argv);
  if (args.help || args.cmd !== "new" || !args.name) { usage(); process.exit(args.help ? 0 : 1); }

  const opts = {
    name: args.name,
    java: args.java || DEFAULTS.java,
    boot: args.boot || DEFAULTS.boot,
    build: args.build || DEFAULTS.build,
    pack: args.pack || DEFAULTS.pack,
    rest: args.webflux ? false : (args.rest ?? DEFAULTS.rest),
    webflux: args.webflux || false,
    apiOnly: args.apiOnly ?? DEFAULTS.apiOnly,
    thymeleaf: !!args.thymeleaf,
    security: args.security ?? DEFAULTS.security,
    jwt: args.jwt ?? DEFAULTS.jwt,
    sessions: !!args.sessions,
    oauth: !!args.oauth,
    cors: args.cors || "*",
    ratelimit: args.ratelimit ?? DEFAULTS.ratelimit,
    openapi: args.openapi ?? DEFAULTS.openapi,
    apiversion: args.apiversion || DEFAULTS.apiversion,
    sqlite: args.sqlite ?? DEFAULTS.sqlite,
    psg: !!args.psg,
    msql: !!args.msql,
    flyway: !!args.flyway,
    liquibase: !!args.liquibase,
    r2dbc: !!args.r2dbc,
    jpa: !!args.jpa,
    mapstruct: !!args.mapstruct,
    paging: !!args.paging,
    redis: !!args.redis,
    kafka: !!args.kafka,
    rabbit: !!args.rabbit,
    es: !!args.es,
    opensearch: !!args.opensearch,
    s3: !!args.s3,
    mail: !!args.mail,
    demosIO: !!args.demosIO,
    demosCPU: !!args.demosCPU,
    demosAsync: !!args.demosAsync,
    resilience: !!args.resilience,
    scheduled: !!args.scheduled,
    sse: !!args.sse,
    ws: !!args.ws,
    grpc: !!args.grpc,
    graphql: !!args.graphql,
    metrics: !!args.metrics,
    otel: !!args.otel,
    logjson: !!args.logjson,
    actuator: !!args.actuator,
    docker: !!args.docker,
    nginx: !!args.nginx,
    ci: !!args.ci,
    port: args.port || DEFAULTS.port
  };

  if (opts.flyway && opts.liquibase) die("Choose only one migrations tool: --flyway OR --liquibase.");
  if (!opts.rest && !opts.webflux) opts.rest = true;

  const root = path.resolve(process.cwd(), opts.name);
  if (fs.existsSync(root) && fs.readdirSync(root).length) die(`Directory '${opts.name}' exists and is not empty.`);

  // Java ids
  const groupId = "com.example";
  const artifactId = toArtifactId(opts.name);
  const packageName = toPackageName(opts.name);
  const packagePath = toPackagePath(packageName);

  // Compose prompts
  let includeComposeApi=false, includePostgres=false, includeMySQL=false, includeRedis=false, includeNginx=false;
  if (opts.docker) {
    includeComposeApi = await yn("Include API in docker-compose?");
    if (opts.psg) includePostgres = await yn("Include Postgres in compose?");
    if (opts.msql) includeMySQL    = await yn("Include MySQL in compose?");
    if (opts.redis) includeRedis   = await yn("Include Redis in compose?");
    if (opts.nginx) includeNginx   = await yn("Include NGINX reverse proxy in compose?");
  }

  log(`\nScaffolding '${opts.name}'...\n`);

  // Files
  write(path.join(root, ".gitignore"), `target/\n.idea/\n*.iml\n.mvn/\n.env\n*.log\n`);
  write(path.join(root, "README.md"), readmeMd({ ...opts, artifactId }));

  write(path.join(root, "pom.xml"), pomXml({ ...opts, groupId, artifactId }));

  write(path.join(root, "src/main/resources/application.yml"), appYml({ ...opts, artifactId }));
  write(path.join(root, "src/main/resources/application-dev.yml"), `# dev overrides\n`);
  write(path.join(root, "src/main/resources/application-prod.yml"), `# prod overrides\n`);

  const base = path.join(root, "src/main/java", packagePath);
  write(path.join(base, "Application.java"), applicationJava({ ...opts, packageName }));
  write(path.join(base, "web/MetaController.java"), controllerJava({ ...opts, packageName }));

  if (opts.security) write(path.join(base, "security/SecurityConfig.java"), securityJava({ ...opts, packageName }));
  if (opts.jwt) write(path.join(base, "security/JwtService.java"), jwtJava({ ...opts, packageName }));

  // Auth controller: in-memory vs JPA
  if (opts.jwt && opts.jpa) {
    write(path.join(base, "domain/User.java"), userEntityJava({ ...opts, packageName }));
    write(path.join(base, "domain/UserRepository.java"), userRepoJava({ ...opts, packageName }));
    write(path.join(base, "web/AuthController.java"), authControllerJava_jpa({ ...opts, packageName }));
  } else if (opts.jwt) {
    write(path.join(base, "web/AuthController.java"), authControllerJava_inMemory({ ...opts, packageName }));
  }

  // Docker & compose
  if (opts.docker) {
    write(path.join(root, "Dockerfile"), dockerfile({ ...opts, artifactId }));
    const wantCompose = includeComposeApi || includePostgres || includeMySQL || includeRedis || includeNginx;
    if (wantCompose) {
      write(path.join(root, "compose.yaml"),
        composeYaml(opts, includeComposeApi, includePostgres, includeMySQL, includeRedis, includeNginx)
      );
      if (includeNginx) write(path.join(root, "nginx.conf"), nginxConf(opts));
    }
  }

  // CI
  if (opts.ci) {
    write(path.join(root, ".github/workflows/ci.yml"), `name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up JDK
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '${opts.java}'
      - name: Build
        run: mvn -q -DskipTests package
      - name: Test
        run: mvn -q test
      - name: Docker build
        run: docker build -t ${artifactId}:ci .
`);
  }

  // Data dir (for sqlite file)
  write(path.join(root, "data/.keep"), "");

  log(`✅ Done! Project scaffolded at ./${opts.name}\n`);
  log(`Next:
  cd ${opts.name}
  export JWT_SECRET=$(openssl rand -hex 32)
  mvn -q -DskipTests package
  java -jar target/${artifactId}-0.0.1-SNAPSHOT.jar
  # Docker:
  docker build -t ${artifactId}:latest .
  docker run -p ${opts.port}:${opts.port} -e JWT_SECRET=$JWT_SECRET ${artifactId}:latest
`);
}

// Simple log helper (kept from your version)
function writeLog(logMessage, logDirectory) {
  if (!fs.existsSync(logDirectory)) fs.mkdirSync(logDirectory);
  const d = new Date();
  const date = d.toLocaleDateString('en-US', { year: '2-digit', month: '2-digit', day: '2-digit' });
  const time = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
  const file = 'log-' + (date + ' ' + time).replace(/[\s/\\]/g, '-') + '.log';
  write(path.join(logDirectory, file), String(logMessage) + '\n');
}

try { main(); } catch(e) { writeLog(e, "logs"); process.exit(1); }
