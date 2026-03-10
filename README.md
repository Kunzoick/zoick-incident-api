# Trust-Aware Incident Intelligence API

**Zoick · Spring Boot 3.5 · Java 23 · MariaDB · Redis · JWT**

> "Assume every request is hostile. Treat failure as a feature. Trust must be earned — never assumed."

---

## What This System Is

A RESTful backend API that manages incident reports submitted by users in a hostile environment. Every request is evaluated not just by *who* the user is (role) but by *how trustworthy their behavior has been* (trust score). The two axes never mix.

| ✅ This system IS | ❌ This system is NOT |
|---|---|
| A RESTful backend API | A CRUD demo |
| Security-first by design | A frontend application |
| Contract-driven — explicit request/response models | A microservices playground |
| Failure-aware — Redis down ≠ system down | An AI/ML project |
| Trust-scored per user and per report | A penetration testing tool |
| Suitable as a portfolio anchor | A framework comparison exercise |

---

## The Iron Rule

This is the most important architectural boundary in the system. Every feature was checked against it before being built.

```
ROLE answers:         What are you structurally allowed to do?
TRUST SCORE answers:  How much does the system believe your behavior right now?
```

```
Trust affects:   CAPACITY · SCRUTINY · PRIORITY — never structural permissions
Role affects:    WHAT YOU CAN DO AT ALL — never adjusted by trust score
```

**Hard rules — never violated:**
- `TRUSTED` is not a role. It is a tier derived from `trust_score` at runtime. Never stored.
- Trust score never grants access. Trust score never blocks access structurally.
- Auto-escalation is always an admin action. Trust is a signal, never a trigger.
- `account_locked` is never set directly by trust score. Trust signals abuse. Admin locks.
- Admin endpoints use a fixed rate limit (60 req/min). Never trust-score-derived.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT / CONSUMER                        │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTP Request
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   SERVLET CONTAINER (Tomcat)                    │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  CorrelationFilter  (Ordered.HIGHEST_PRECEDENCE)         │  │
│  │  → Generates X-Correlation-Id UUID                       │  │
│  │  → Sets request attribute + response header              │  │
│  │  → Sets CorrelationContext ThreadLocal                   │  │
│  └─────────────────────────┬────────────────────────────────┘  │
│                            │                                    │
│  ┌─────────────────────────▼────────────────────────────────┐  │
│  │           SPRING SECURITY FilterChainProxy               │  │
│  │                                                          │  │
│  │  ┌───────────────────────────────────────────────────┐  │  │
│  │  │  JwtFilter                                        │  │  │
│  │  │  → Validates JWT signature and expiry             │  │  │
│  │  │  → Extracts userId + role from claims             │  │  │
│  │  │  → Sets SecurityContext                           │  │  │
│  │  └──────────────────────┬────────────────────────────┘  │  │
│  │                         │                                │  │
│  │  ┌──────────────────────▼────────────────────────────┐  │  │
│  │  │  RateLimitFilter                                  │  │  │
│  │  │  → Loads user trust score from DB                 │  │  │
│  │  │  → BLOCKED tier check → 403 TRUST_BLOCKED         │  │  │
│  │  │  → Redis counter check → 429 RATE_LIMIT_EXCEEDED  │  │  │
│  │  │  → Penalizes trust score on violation             │  │  │
│  │  └──────────────────────┬────────────────────────────┘  │  │
│  │                         │                                │  │
│  │  ┌──────────────────────▼────────────────────────────┐  │  │
│  │  │  Spring Security Authorization                    │  │  │
│  │  │  → Role-based endpoint rules                      │  │  │
│  │  │  → 403 INSUFFICIENT_ROLE on wrong role            │  │  │
│  │  └──────────────────────┬────────────────────────────┘  │  │
│  └─────────────────────────┼────────────────────────────────┘  │
└───────────────────────────-┼────────────────────────────────────┘
                             │
             ┌───────────────▼───────────────┐
             │          CONTROLLERS          │
             │  AuthController               │
             │  IncidentController           │
             │  AdminController              │
             └───────────────┬───────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
       ▼                     ▼                     ▼
┌─────────────┐   ┌──────────────────┐   ┌─────────────────┐
│ AuthService │   │ IncidentService  │   │TrustScoreService│
│             │   │                  │   │                 │
│ register    │   │ submit           │   │ applyDelta()    │
│ login       │   │ view             │   │ single source   │
│ refresh     │   │ duplicate check  │   │ of truth for    │
│ logout      │   │ credibility score│   │ all mutations   │
└──────┬──────┘   └────────┬─────────┘   └────────┬────────┘
       └──────────────────-┴─────────────────────-─┘
                             │
             ┌───────────────▼───────────────┐
             │           DATA LAYER          │
             │                               │
             │  MariaDB (source of truth)    │
             │  ├── users                    │
             │  ├── incidents                │
             │  ├── refresh_tokens           │
             │  ├── trust_score_history      │
             │  ├── incident_corroborations  │
             │  └── audit_logs               │
             │                               │
             │  Redis (rate limiting only)   │
             │  ├── rate:user:{userId}        │
             │  └── rate:admin:{userId}       │
             └───────────────────────────────┘
```

---

## Security Design

The security model has three independent layers. Each layer has a single responsibility and cannot be bypassed by the others.

### Layer 1 — Authentication (JwtFilter)
Every request to a protected endpoint must carry a valid JWT access token. JwtFilter validates the token signature and expiry on every request. If the token is invalid, expired, or missing, the request is rejected before reaching any business logic. Spring Security handles unauthenticated requests before JwtFilter even runs.

### Layer 2 — Behavioral Rate Limiting (RateLimitFilter)
After authentication establishes *who* the user is, RateLimitFilter checks *how many requests they are allowed* based on their trust tier. Two checks happen in order:

1. **BLOCKED tier check** — if trust score is below 20, the request is rejected with `403 TRUST_BLOCKED`. Redis is never touched for a BLOCKED user.
2. **Rate limit check** — Redis counter is checked against the tier's limit. Exceeding it returns `429 RATE_LIMIT_EXCEEDED` and deducts 2 trust points.

### Layer 3 — Role-Based Authorization (Spring Security)
Spring Security enforces which roles can access which endpoints. A USER cannot reach admin endpoints. An unauthenticated request cannot reach any protected endpoint. This layer is purely structural — trust score never influences it.

### What Each Layer Cannot Do
- JwtFilter cannot check rate limits — it has no trust tier information
- RateLimitFilter cannot grant structural access — it can only allow or deny based on capacity
- Spring Security authorization cannot be softened by trust score — role is role

---

## Token Strategy

### Why JWT Access Tokens With a 5-Minute TTL
Access tokens are stateless JWTs. The server does not store them. Validation is purely cryptographic — signature check plus expiry check. This means authentication never requires a database read on the critical path.

The 5-minute TTL is deliberately short. A stolen access token is only useful for up to 5 minutes. The alternative is token blacklisting — checking Redis on every request. If Redis is unavailable, authentication breaks entirely. This system treats Redis as a non-critical component. Short TTL achieves comparable protection without the Redis dependency.

### Why Opaque Refresh Tokens Stored Hashed in the Database
Refresh tokens are long-lived (7 days) and must be revocable. JWTs cannot be revoked without blacklisting. Opaque UUIDs stored SHA-256 hashed in the database can be revoked instantly by deleting the record. The hash means that if the database is breached, raw refresh tokens are not exposed.

### Token Rotation on Every Refresh
Every time a refresh token is used, it is immediately revoked and a new token pair is issued. The window during which a stolen refresh token is usable is limited to the gap between theft and the next legitimate refresh.

### Reuse Detection
If a refresh token that has already been revoked is presented again, the system treats this as evidence of token theft. The entire token family is revoked atomically — all sessions on that device are terminated. Response is `401 TOKEN_REUSE_DETECTED` and trust score is penalized -15.

### tokenVersion
Each user has a `tokenVersion` integer. Admins can increment it to force all existing sessions to expire at the next refresh — used after a confirmed account compromise. Checked at refresh time only, not on every access token validation, to avoid a database read per request.

---

## Failure Scenarios

### Scenario 1 — Redis Goes Down
```
Request arrives
→ CorrelationFilter: assigns correlation ID ✓
→ JwtFilter: validates JWT — no Redis involved ✓
→ RateLimitFilter: attempts Redis counter increment
→ Redis throws connection exception
→ RateLimitService catches exception
→ logs REDIS_UNAVAILABLE at WARN level
→ returns allowed = true (fail open)
→ request reaches controller normally ✓
```
System continues operating. Rate limiting is temporarily unenforced. No user is denied. No auth impact.

### Scenario 2 — Token Reuse Detected
```
Attacker presents a stolen refresh token that has already been rotated
→ AuthService looks up token hash in DB
→ Token found but status = REVOKED
→ Entire token family revoked atomically (DB transaction)
→ TrustScoreService.penalizeTokenReuse() → -15 trust score
→ userRepository.incrementTokenVersion()
→ Response: 401 TOKEN_REUSE_DETECTED
→ All active sessions for that device terminated
```
Attacker's token is useless. All events written to audit_log with correlationId.

### Scenario 3 — User Hits Rate Limit
```
STANDARD user (score 50-79, limit 10/min) sends 11th request
→ JwtFilter: validates token, sets SecurityContext
→ RateLimitFilter: loads user from DB
→ Tier = STANDARD, not BLOCKED → proceed to Redis check
→ Redis counter = 11, limit = 10 → exceeded
→ TrustScoreService.penalizeRateLimit() → -2 trust score
→ Response: 429 RATE_LIMIT_EXCEEDED
```
Request rejected. If violations continue, score drops to RESTRICTED (3/min) then BLOCKED (0/min).

### Scenario 4 — Duplicate Submission
```
User submits incident with same title + description within 24 hours
→ IncidentService computes SHA-256(title + "||" + description)
→ Queries DB: same user_id + same content_hash + within 24h window → match found
→ TrustScoreService.penalizeDuplicate() → -5 trust score
→ Audit log entry written
→ Response: 409 DUPLICATE_SUBMISSION
```
The same content from a *different* user is allowed — independent reports of the same event are valid corroboration signal.

### Scenario 5 — account_locked and BLOCKED Tier Simultaneously
```
User has trust_score = 10 AND account_locked = true
→ Login attempt → AuthService checks account_locked → 403 ACCOUNT_LOCKED
→ Even if authenticated → RateLimitFilter checks BLOCKED tier → 403 TRUST_BLOCKED
```
Both mechanisms apply independently at separate layers. Neither clears the other. Admin must explicitly clear `account_locked`. Trust score must rise above 20 for BLOCKED tier to recover automatically.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 23 |
| Framework | Spring Boot 3.5.1 |
| Build | Maven |
| Database | MariaDB (MySQL 5.5 compatible) |
| Cache / Rate Limiting | Redis (Memurai on Windows) |
| Schema Migrations | Flyway — Hibernate DDL is disabled |
| Auth | Spring Security + JWT (jjwt 0.12.6) |
| Utilities | Lombok, Spring Data JPA, Spring Actuator |

---

## Prerequisites

- Java 23 installed
- MariaDB running locally on port 3306
- Redis running locally on port 6379 (Memurai recommended on Windows)
- Maven 3.8+

---

## Setup

### 1. Clone the repository

```bash
git clone <repo-url>
cd incidentapi
```

### 2. Create the database

```sql
CREATE DATABASE zoick_incidentapi;
```

### 3. Configure environment variables

The application expects secrets via environment variables — never hardcoded:

```
DB_URL=jdbc:mysql://localhost:3306/zoick_incidentapi?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC
DB_USERNAME=your_db_user
DB_PASSWORD=your_db_password
JWT_SECRET=your_jwt_secret_min_32_chars
REDIS_HOST=localhost
REDIS_PORT=6379
```

### 4. Run the application

```bash
mvn spring-boot:run
```

Flyway automatically runs all migrations on startup. The database schema and seed admin account are created automatically.

### 5. Verify

```
GET http://localhost:8080/actuator/health
```

Expected: `{"status":"UP"}`

---

## Seed Admin Account

Created automatically by Flyway V1 migration. No bootstrap endpoint exists — admin accounts are provisioned via migration only.

```
Email:    admin@zoick.com
Password: Admin@Zoick123
```

---

## API Overview

All endpoints are versioned under `/api/v1`.

### Authentication

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | None | Register a new user |
| POST | `/api/v1/auth/login` | None | Login, receive token pair |
| POST | `/api/v1/auth/refresh` | None | Rotate refresh token |
| POST | `/api/v1/auth/logout` | Bearer | Invalidate refresh token |

### Incidents (User)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/incidents` | Bearer USER | Submit an incident report |
| GET | `/api/v1/incidents` | Bearer USER | View own incidents (paginated) |
| GET | `/api/v1/incidents/{id}` | Bearer USER | View a specific own incident |

### Incidents (Admin)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/admin/incidents` | Bearer ADMIN | View all incidents (paginated, credibility-ordered) |
| PATCH | `/api/v1/admin/incidents/{id}/review` | Bearer ADMIN | Set confirmed severity and status |
| PATCH | `/api/v1/admin/incidents/{id}/escalate` | Bearer ADMIN | Escalate an incident |

---

## HTTP Contract

Every error response has this exact shape — no exceptions:

```json
{
  "status": 403,
  "error": "TRUST_BLOCKED",
  "message": "Your trust score is too low to make requests.",
  "path": "/api/v1/incidents",
  "timestamp": "2026-03-07T14:27:18.144",
  "correlationId": "d75e93b9-cf8f-48cb-86b7-38a2d0f8003d"
}
```

### Status Code Contract

| Scenario | Status | Error Code |
|---|---|---|
| Token invalid/malformed | 401 | `INVALID_TOKEN` |
| Access token expired | 401 | `TOKEN_EXPIRED` |
| Refresh token revoked | 401 | `TOKEN_REVOKED` |
| Token reuse detected | 401 | `TOKEN_REUSE_DETECTED` |
| Account locked | 403 | `ACCOUNT_LOCKED` |
| Trust tier BLOCKED | 403 | `TRUST_BLOCKED` |
| Accessing another user's resource | 403 | `ACCESS_DENIED` |
| Wrong role for endpoint | 403 | `INSUFFICIENT_ROLE` |
| Rate limit exceeded | 429 | `RATE_LIMIT_EXCEEDED` |
| Duplicate submission | 409 | `DUPLICATE_SUBMISSION` |
| Validation failure | 400 | `VALIDATION_ERROR` |
| Resource not found | 404 | `RESOURCE_NOT_FOUND` |
| Internal error | 500 | `INTERNAL_ERROR` |

---

## Architecture & Design Decisions

### DDR-001 — Authentication & Token Lifecycle

- **Access token:** JWT, 5-minute TTL, claims: `userId`, `role`, `tokenVersion`
- **Refresh token:** Opaque UUID, stored SHA-256 hashed in DB, bound to `userId` + `deviceId`
- **Rotation:** On every refresh, old token is revoked and new token pair is issued
- **Reuse detection:** Revoked token presented → entire token family revoked → `401 TOKEN_REUSE_DETECTED`
- **`tokenVersion`** checked at refresh time only — not on every access token validation
- **Logout:** Deletes refresh token from DB. Access token expires naturally within 5 minutes
- **Redis is never touched for auth** — zero auth impact if Redis goes down

**Why not token blacklisting?**
Redis failure would break authentication entirely. Stateless JWT with short TTL is the correct tradeoff — stolen access token is valid for up to 5 minutes. This residual risk is accepted and documented.

### DDR-002 — Trust Score System

Every user has an integer trust score (0–100), starting at 50 (neutral).

**Currently implemented score events:**

| Event | Delta | Triggered By |
|---|---|---|
| Report validated by admin | +10 | Admin review action |
| Duplicate submission | -5 | IncidentService |
| Rate limit hit | -2 | RateLimitFilter |
| Spam flagged by admin | -10 | Admin review action |
| Token reuse detected | -15 | AuthService |

**Planned score events (not yet implemented):**

| Event | Delta | Notes |
|---|---|---|
| Clean behavior week | +5 | Requires scheduled batch job |
| No violations | +2 | Requires scheduled batch job |

**Trust Tiers (derived at runtime, never stored):**

| Score | Tier | Rate Limit | Corroboration Weight |
|---|---|---|---|
| 80–100 | TRUSTED | 20 req/min | +15 |
| 50–79 | STANDARD | 10 req/min | +10 |
| 20–49 | RESTRICTED | 3 req/min | +3 |
| 0–19 | BLOCKED | 0 req/min | +0 |

`TrustTier.fromScore(int)` is the **only** place thresholds are defined. Every other class calls that method — no class hardcodes threshold numbers.

### DDR-003 — account_locked vs BLOCKED Tier

These are two independent security mechanisms checked at separate layers:

| | `account_locked` | BLOCKED Tier |
|---|---|---|
| Threat type | Security threat | Behavioral threat |
| Trigger | Failed login attempts threshold | Trust score drops below 20 |
| Layer | Auth layer | Service layer |
| Recovery | Admin clears manually | Automatic when score rises |
| Response | `403 ACCOUNT_LOCKED` | `403 TRUST_BLOCKED` |

Both can apply simultaneously. Neither causes the other.

### DDR-004 — Duplicate Detection

- Per-user, hash-based, 24-hour window
- Algorithm: `SHA-256(title + "||" + description)` = `content_hash`
- The `||` separator prevents hash collisions — `"AB||CD"` and `"A||BCD"` produce different hashes
- Same `user_id` + same `content_hash` + submitted within 24 hours = `409 DUPLICATE_SUBMISSION`
- Cross-user detection explicitly rejected — independent reports of the same event are real signal
- Duplicate trigger = `-5` trust score + audit log entry

### DDR-005 — Incident Credibility Score

Every incident has a `credibility_score` initialized from the submitter's trust score at submission time:

```
credibility = MIN(100, submitter_trust_at_submission + SUM(tier weights of corroborators))
```

- Admin-only corroboration action — algorithmic corroboration was explicitly rejected because it can be gamed by coordinated fake accounts
- Written to `incident_corroborations` table + audit log

---

## Trust Score Architecture

`TrustScoreService` is the **single source of truth** for all trust score mutations. No other class modifies `trust_score` directly.

```
AuthService          → penalizeTokenReuse()
IncidentService      → penalizeDuplicate(), rewardValidatedReport(), penalizeSpam()
RateLimitFilter      → penalizeRateLimit()
AdminController      → adminOverride()
```

Every mutation: clamps to 0–100 → writes `trust_score_history` → writes `audit_log` → logs with `correlationId`.

---

## Rate Limiting Architecture

**Redis key schema:**
```
rate:user:{userId}   → per-user bucket, limit from TrustTier.getRequestsPerMinute()
rate:admin:{userId}  → admin bucket, fixed 60 req/min, never trust-score-derived
```

**Filter execution order:**
```
CorrelationFilter  → sets correlation ID (runs before Spring Security)
JwtFilter          → establishes who the user is
RateLimitFilter    → checks how many requests they are allowed
Controllers        → only reached if all three pass
```

**Fail-open behavior:** Redis unavailable → log `REDIS_UNAVAILABLE` → allow request → continue. Redis holds no source of truth. Its unavailability never denies a legitimate user.

---

## Observability

Every request gets a unique `X-Correlation-Id` UUID generated by `CorrelationFilter` before anything else runs. `CorrelationFilter` is registered via `FilterRegistrationBean` with `Ordered.HIGHEST_PRECEDENCE` — it runs at the servlet container level before Spring Security's `FilterChainProxy`. This ID flows through:

- Request attribute (readable by all filters and services)
- `CorrelationContext` ThreadLocal (readable by `GlobalExceptionHandler` via fallback)
- Response header (returned to caller for end-to-end tracing)
- Every log line from every service
- Every error response body

Any request in the system is fully traceable by correlation ID alone.

---

## Database Schema

| Table | Purpose |
|---|---|
| `users` | User accounts with trust score, lock state, and optimistic lock version |
| `incidents` | Incident reports with credibility score and state machine status |
| `refresh_tokens` | Hashed refresh tokens with family tracking for reuse detection |
| `trust_score_history` | Immutable record of every trust score change |
| `incident_corroborations` | Admin-linked corroborating incidents |
| `audit_logs` | Immutable security event records |

All migrations are in `src/main/resources/db/migration`. Hibernate DDL is disabled — Flyway owns the schema exclusively.

**Schema notes:**
- `trust_score_history.changed_by` and `audit_logs.actor_id` do not have FK constraints — they must accept both user UUIDs and the system identifier `"SYSTEM"` for automated penalties
- All domain entities with manually-assigned UUIDs use `EntityManager.persist()` directly — Spring Data's `save()` calls `merge()` when the ID is non-null, which skips `updatable=false` columns on insert

---

## Failure Handling Matrix

| Failure | Response | Notes |
|---|---|---|
| Redis unavailable | Fail open, log warning, continue | Redis holds no source of truth |
| MySQL unavailable | `503`, log with correlation ID | `@Transactional` ensures no half-state |
| JWT malformed | `401 INVALID_TOKEN`, no detail leaked | Read-only, no state change |
| Token reuse | Revoke family atomically, `401` | Atomic DB transaction |
| Duplicate submit | `409`, deduct -5 trust, log | Same transaction |
| Rate limit hit | `429`, deduct -2 trust, log | Trust deduction is async — occasional loss acceptable |
| Account locked | `403 ACCOUNT_LOCKED` | Read-only check |
| BLOCKED tier | `403 TRUST_BLOCKED` | Read-only check before Redis is touched |

---

## Known Limitations

### IP-Level Rate Limiting (Deferred)
Unauthenticated endpoints (`/auth/register`, `/auth/login`) have no IP-level rate limiting. Login brute force is mitigated by `account_locked` after 5 failed attempts. IP-level limiting was deferred because it introduces NAT, proxy, and shared IP complexity that is out of scope. Documented as a future evolution path.

### Redis Key Eviction Under Memory Pressure
If Redis evicts rate limiting keys under extreme memory pressure, affected users get a free window reset. This temporarily relaxes capacity enforcement but does not grant structural access — The Iron Rule holds regardless. Mitigation in production: set `maxmemory-policy noeviction` on the Redis instance.

### 5-Minute Access Token Blast Radius
A stolen access token is valid for up to 5 minutes. This is a documented, accepted tradeoff. The alternative (token blacklisting via Redis) would make auth dependent on Redis availability — a worse tradeoff for this threat model.

### Trust Score DB Read Per Request
Trust score is read from the database on every authenticated request. A Redis cache with 30-second TTL and explicit invalidation on score change is the documented evolution path — not yet built.

### Scheduled Trust Score Events Not Yet Implemented
Reward events for sustained clean behavior (+5 per week, +2 for no violations) require a scheduled batch job. The deltas are defined in DDR-002 but the scheduler does not yet exist. Documented as a known evolution path.

---

## Known Evolution Paths

These were explicitly scoped out and documented — not forgotten:

- Redis cache for trust score (30s TTL + explicit invalidation on score change)
- IP-level rate limiting for unauthenticated routes
- Batch trust score decay and reward job (paginated, indexed on `last_active_at`, off-peak)
- User-initiated corroboration with trust-weighted approval
- Cross-user content similarity detection
- IP-level coordinated abuse pattern detection

---

## Project Structure

```
src/main/java/com/zoick/incidentapi/
├── audit/              # AuditEventType enum
├── config/             # RedisConfig
├── controller/         # AuthController, IncidentController, AdminController
├── domain/             # JPA entities and domain enums
├── dto/                # Request and response DTOs
├── exception/          # GlobalExceptionHandler, custom exceptions
├── repository/         # Spring Data JPA repositories
├── security/           # JwtFilter, RateLimitFilter, CorrelationFilter, SecurityConfig
└── service/            # AuthService, IncidentService, TrustScoreService, RateLimitService

src/main/resources/
├── application.yml
└── db/migration/       # V1 through V8 Flyway migrations
```

---

## Further Reading

- [Architecture Decision Document](docs/Architecture_Decision_Document.docx) — full architectural reasoning, every design decision, what was rejected and why, and real problems solved during the build
- [Postman Collection](docs/api-collection.json) — import into Postman to test all endpoints locally. Requires the app running on port 8080 with a registered user.
