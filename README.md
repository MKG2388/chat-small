# CODW RAG App

NL2SPARQL RAG assistant for Dutch government rule specifications. Translates natural language questions into SPARQL queries and generates answers from the results.

## Architecture

- **Streamlit** app with an OpenAI-compatible LLM backend
- **Keycloak** OIDC authentication (auto-redirect, PKCE, token expiry)
- **SPARQL** queries against the CODW TriplyDB endpoint
- **Traefik** reverse proxy with TLS in production

## Quick start (dev)

```bash
cp .env.example .env
# Edit .env with your values
docker compose up -d
```

The app is at `http://localhost:8501`, Keycloak admin at `http://localhost:8080` (admin/admin).

To disable authentication, leave `OIDC_AUTHORITY` empty in `.env`.

## Production deployment

Assumes an existing Traefik instance with a `traefik` Docker network and a Keycloak instance on `keycloak.example.com`.

```bash
cp .env.prod.example .env
# Edit .env — set OIDC_CLIENT_SECRET, DEFAULT_API_BASE_URL, DEFAULT_API_MODEL
docker compose -f docker-compose.prod.yml up -d
```

The app will be available at `https://codw.example.com`.

### Keycloak realm setup (prod)

Import `keycloak/realm-export-prod.json` into your Keycloak instance to create the `codw` realm and `codw-app` client.

#### Via the admin console (GUI)

1. Log in to the Keycloak admin console (e.g. `https://keycloak.example.com/admin`)
2. Hover over the realm name in the top-left dropdown and click **Create realm**
3. Click **Browse...** and select `keycloak/realm-export-prod.json`
4. Click **Create**
5. Go to **Clients** > **codw-app** > **Credentials** tab
6. Click **Regenerate** to generate a new client secret
7. Copy the secret and set it as `OIDC_CLIENT_SECRET` in your `.env`

#### Via CLI

```bash
/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin
/opt/keycloak/bin/kcadm.sh create partialImport -r codw -s ifResourceExists=SKIP -f /path/to/realm-export-prod.json
```

After importing, set the client secret in Keycloak to match the `OIDC_CLIENT_SECRET` in your `.env`.

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OIDC_AUTHORITY` | Keycloak realm URL (external/browser-facing). Leave empty to disable auth | — |
| `OIDC_INTERNAL_AUTHORITY` | Keycloak realm URL for server-to-server calls (inside Docker) | same as `OIDC_AUTHORITY` |
| `OIDC_CLIENT_ID` | OIDC client ID | — |
| `OIDC_CLIENT_SECRET` | OIDC client secret | — |
| `OIDC_REDIRECT_URI` | OAuth2 redirect URI (your app's public URL) | `http://localhost:8501` |
| `SPARQL_ENDPOINT` | SPARQL endpoint URL | — |
| `DEFAULT_API_BASE_URL` | Pre-filled LLM API base URL in the sidebar | — |
| `DEFAULT_API_MODEL` | Pre-filled model name in the sidebar | `gpt-4o-mini` |

## Adding users to the realm (dev)

Users are defined in `keycloak/realm-export.json` under the `"users"` array. Add a new entry:

```json
{
  "username": "jan",
  "email": "jan@example.com",
  "enabled": true,
  "firstName": "Jan",
  "lastName": "de Vries",
  "credentials": [
    {
      "type": "password",
      "value": "a-secure-password",
      "temporary": false
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `username` | Login name |
| `email` | Email address |
| `enabled` | `true` to allow login, `false` to disable |
| `firstName` / `lastName` | Display name |
| `credentials[].value` | Password (plaintext in JSON — Keycloak hashes on import) |
| `credentials[].temporary` | `true` to force password change on first login |

The realm JSON is only imported on **first startup**. To re-import after changes:

```bash
docker compose down -v   # removes keycloak data volume
docker compose up -d     # re-imports the realm
```

**Production:** manage users via the Keycloak admin console at `https://keycloak.example.com` instead of editing JSON files.

## Running without Docker

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Set env vars (or export from .env)
export OIDC_AUTHORITY=http://localhost:8080/realms/codw
export OIDC_CLIENT_ID=codw-app
export OIDC_CLIENT_SECRET=change-me-in-production
export DEFAULT_API_BASE_URL=https://api.openai.com/v1
export DEFAULT_API_MODEL=gpt-4o-mini

streamlit run app.py
```
