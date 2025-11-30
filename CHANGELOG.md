# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-01

### Added

- **Core SDK**
  - Complete implementation of JTS Specification v1.1
  - Support for all three profiles: JTS-L (Lite), JTS-S (Standard), JTS-C (Confidentiality)
  - BearerPass and StateProof token generation and validation
  - Asymmetric cryptography with RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512 algorithms
  - JWE encryption support for JTS-C profile (RSA-OAEP + A256GCM)

- **Crypto Utilities**
  - Key pair generation (RSA and EC)
  - Digital signature creation and verification
  - DER encoding fixes for ES512 signatures
  - Base64URL encoding/decoding
  - JWKS conversion utilities
  - AES-GCM encryption/decryption
  - Secure random generation

- **Session Management**
  - Abstract `SessionStore` interface
  - `InMemorySessionStore` for development/testing
  - `RedisSessionStore` for production (requires `ioredis`)
  - `PostgresSessionStore` for production (requires `pg`)
  - StateProof rotation with grace window support
  - Replay attack detection (JTS-S/C)
  - Device fingerprint binding

- **Server SDK**
  - `JTSAuthServer` - Complete authentication server implementation
  - `JTSResourceServer` - Token verification for protected resources
  - Key rotation support with JWKS endpoint generation
  - Session policy enforcement (single session, max sessions)

- **Client SDK**
  - `JTSClient` - Browser/Node.js client for JTS authentication
  - Auto token renewal before expiration
  - Event handlers for token refresh and expiration
  - Pluggable token storage interface

- **Express Middleware**
  - `jtsAuth()` - Protect routes with JTS authentication
  - `jtsOptionalAuth()` - Optional authentication
  - `jtsRequirePermissions()` - Permission-based access control
  - `createJTSRoutes()` - Pre-built login/renew/logout handlers
  - `mountJTSRoutes()` - Quick setup with default routes
  - CSRF protection via `X-JTS-Request` header

- **CLI Tools**
  - `jts keygen` - Generate RS256/ES256/etc key pairs
  - `jts inspect` - Decode and display token contents
  - `jts verify` - Verify token signatures
  - `jts jwks` - Convert keys to JWKS format
  - `jts init` - Generate starter configuration

- **Error Handling**
  - Standardized JTS error codes (JTS-4xx-xx, JTS-5xx-xx)
  - `JTSError` class with HTTP status, action hints
  - Consistent error responses across all components

- **Testing**
  - 256 unit tests covering all components
  - >80% code coverage
  - Tests for crypto, tokens, stores, server, middleware

### Security

- All cryptographic operations use Node.js native `crypto` module
- No external JWT libraries - full control over token handling
- Private keys never exposed in JWKS endpoints
- Secure random generation for all tokens and IDs
- CSRF protection on mutating endpoints

### Documentation

- Complete API reference in README
- Inline JSDoc comments
- Example code for all major features
- JTS Specification v1.1 included

---

## [Unreleased]

### Planned

- JWKS auto-fetch from remote endpoints
- Token introspection endpoint
- Session listing and management UI
- Rate limiting utilities
- Prometheus metrics integration
- OpenTelemetry tracing support
