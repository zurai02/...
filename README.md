# Luau Delivery

A production-oriented Luau script delivery platform for authorized
Roblox clients and developer workflows.

## Security model

This project does NOT claim that Luau source delivered to an
untrusted Roblox client can remain secret.

Once source code reaches a client, the client may potentially:

- inspect it
- copy it
- dump it
- instrument it
- reverse engineer it

The platform instead protects:

- administrative resources
- API credentials
- source repositories
- deployment credentials
- internal implementation
- access permissions
- token lifetime
- delivery rate
- audit information

For sensitive functionality, keep the logic server-side.

## Features

- Luau/Lua script support
- Script versioning
- SHA-256 integrity hashes
- Raw text endpoint
- Scoped bearer tokens
- Short-lived access tokens
- Authentication
- Authorization
- Rate limiting
- Security headers
- CORS configuration
- Audit logs
- SQLite persistence
- Docker support
- GitHub Actions
- Dependency auditing
- Secret scanning
- Luau validation
- Minimal raw responses

## Installation

Requirements:

- Node.js 20+
- npm

Install:

```bash
npm ci
