# ZGW JWT tokens Introspection Provider for Keycloak

This provider adds ZGW token verification and parsing to Keycloak. It exposes a realm endpoint that validates HS256-signed ZGW JWTs by looking up the token's `client_id` in Keycloak and verifying the signature with that client's secret, returning an OAuth2 token introspection response.

## Overview

Introspection endpoint:
- Requires a `client_id` claim
- Resolves the Keycloak client by `client_id` and verifies the HS256 signature using that client's secret stored in Keycloak (no external secret store)
- Includes claims from any OIDC Hardcoded Claim protocol mappers configured in keycloak, on the client
- Enforces token activity (validates `exp`/`nbf` when present)
- Tokens without `exp` claim will be treated as active, but warning will be logged in keycloak. It's recommended to use short lived tokens.

## Build

1. Ensure you have Java 21 installed (download from https://learn.microsoft.com/en-us/java/openjdk/download)
2. Download Maven `Binary zip archive` from https://maven.apache.org/download.cgi
3. Add the bin directory of the created directory apache-maven-* to the PATH environment variable
4. Run the following command to build the JAR:
   ```bash
   mvn clean package
   ```
5. The compiled JAR will be in the `target/` directory: `zgw-token-introspection.jar`

## Deployment

1. Copy the JAR file to your Keycloak deployment:
   - For host install: `{KEYCLOAK_HOME}/providers/`
   - For Docker: mount to `/opt/keycloak/providers/`

2. Restart Keycloak. In dev:
   - `{KEYCLOAK_HOME}/bin/kc.sh start-dev`
   In prod:
   - `{KEYCLOAK_HOME}/bin/kc.sh build && {KEYCLOAK_HOME}/bin/kc.sh start`

## Endpoint

- Path: `/realms/{realm}/zgw-token-introspection/introspect`
- Method: `POST`
- Content-Type: `application/x-www-form-urlencoded`
- Parameter: `token=<JWT>`

## Token requirements

The provider expects JWT tokens generated with the following characteristics:

- **Algorithm**: HS256
- **Secret**: Client secret from Keycloak
- **Required claim**: `client_id` (must match a client in the realm)
- **Temporal**: Token must be active; `exp` is recommended


## Usage

Submit the token to the introspection endpoint:
```bash
curl -X POST \
  "http://localhost:8080/realms/{realm}/zgw-token-introspection/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```
Returns an OAuth2 introspection-style payload with selected standard and custom claims.
On success you will receive `{ "active": true, ... }` and claim from token; otherwise `{ "active": false }`.

## Troubleshooting

- Check Keycloak logs for detailed error messages
- Ensure the client exists in Keycloak and has a secret configured
- Verify the token is properly formatted and not expired
- Confirm the signing algorithm is HS256
- Make sure the client secret matches what was used to sign the token
