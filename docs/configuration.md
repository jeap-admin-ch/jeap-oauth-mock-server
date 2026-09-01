# Configuration

The mock server is configured through two property groups:

- `mockserver.*` for server-wide behavior (issuer URL, public endpoint generation and introspection audience-check mode)
- `oauth-mock-data.*` for clients, users, and roles pruning

## Server base URL

```yaml
mockserver:
  base-url: "http://localhost:8180"
```

The value becomes the OpenID issuer and is used together with the fixed JWK path `/.well-known/jwks.json`.

## Full example

```yaml
mockserver:
  base-url: "http://localhost:8180"
  introspection-endpoint-audience-check: "off"

oauth-mock-data:
  clients:
    - client-id: "example-client"
      client-secret: "{noop}secret"
      introspection-endpoint-audience-check: "warn"
      registered-redirect-uri:
        - "http://localhost:4200/startpage"
        - "http://localhost:4200/silent-refresh.html"
      registered-post-logout-redirect-uri:
        - "http://localhost:4200/"
      access-token-validity-seconds: 3600
      refresh-token-validity-seconds: 3600
      context: "USER"
      subject: "custom-subject"
      audience: [ "example-resource" ]
      scope: [ "openid" ]
      userroles: [ "partner-read", "partner-write", "partners-list" ]
      bproles:
        "12345": [ "partner-read" ]
        "67890": [ "partner-read", "partner-write" ]
      bproles-scope-enabled: true
      roles-pruning-enabled: true

  users:
    - id: "user"
      given-name: "Henriette"
      family-name: "Muster"
      email: "henriette@muster.domain"
      locale: "DE"
      preferred-username: "12345"
      ext-id: "1123"
      admin-dir-uid: "U12345678"
      login-level: "S3"
      subject: "user-subject"
      userroles: [ "partners-list" ]
      bproles:
        "12345": [ "partner-read" ]
        "67890": [ "partner-read" ]
      additional-claims:
        acr: "urn:example:loa:substantial"

  roles-pruning-limit: 8000
```

## `oauth-mock-data.clients[]`

Each entry defines one OAuth client.

| Property | Type | Required | Meaning |
|---|---|---:|---|
| `client-id` | string | yes | OAuth client id |
| `client-secret` | string | no | Secret for authenticated clients; usually required for `client_credentials` |
| `registered-redirect-uri` | list of strings | no | Allowed redirect URIs for `authorization_code`; wildcard suffix `*` is supported |
| `registered-post-logout-redirect-uri` | list of strings | no | Allowed exact redirect URIs after an OpenID Connect end-session request |
| `access-token-validity-seconds` | number | no | Access-token lifetime in seconds; default is 3600 |
| `refresh-token-validity-seconds` | number | no | Refresh-token lifetime in seconds; default is 3600 |
| `context` | `USER`, `SYS`, `B2B` | no | If set, fixes both the grant type and client authentication methods |
| `subject` | string | no | Static subject to use when no user-specific subject/preferred username applies |
| `audience` | list of strings | no | Value written to the `aud` claim for access tokens |
| `scope` | list of strings | no | Additional allowed scopes; OIDC standard scopes are always added automatically |
| `userroles` | list of strings | no | Default `userroles` claim for this client |
| `bproles` | map string to list of strings | no | Default `bproles` claim for this client |
| `bproles-scope-enabled` | boolean | no | Enables the dynamic scope pattern `bproles:*`; default `false` |
| `roles-pruning-enabled` | boolean | no | Adds the `roles-pruning` scope so access tokens can prune oversized role claims |
| `introspection-endpoint-audience-check` | `off`, `warn`, `on` | no | Client-specific override for introspection audience validation mode |

### `context`

`AuthContext` currently supports these values:

- `USER`: `authorization_code`, client auth methods `none` and `client_secret_post`
- `SYS`: `client_credentials`, client auth methods `client_secret_basic` and `client_secret_post`
- `B2B`: same technical behaviour as `SYS`

If `context` is omitted, the server accepts `client_credentials` by default and also adds `authorization_code` when
`registered-redirect-uri` is configured.

The optional `registered-post-logout-redirect-uri` list controls redirects requested with `post_logout_redirect_uri`
at the OpenID Connect end-session endpoint. The requested URI must exactly match a configured value. When the property
is omitted, post-logout redirects remain disabled.

### Scopes

Configured scopes are merged with the standard OIDC scopes:

- `openid`
- `profile`
- `email`
- `phone`
- `address`

If `bproles-scope-enabled` is `true`, the client automatically also allows `bproles:*`.
If `roles-pruning-enabled` is `true`, the client automatically also allows `roles-pruning`.

### Dynamic bproles scope

Dynamic scopes were added in version `2.23.0`.

When `bproles-scope-enabled` is enabled, a request can ask for:

- `bproles:*` to keep all configured business-partner roles
- `bproles:<business-partner-id>` to keep only one partner's roles in the `bproles` claim

If no `bproles:...` scope is requested, the `bproles` claim is removed entirely for that token.

### Roles pruning

Roles pruning is available in current code and is enabled per client with `roles-pruning-enabled` plus the requested
scope `roles-pruning`.

When the combined serialized size of `userroles` and `bproles` exceeds `oauth-mock-data.roles-pruning-limit`
(default `8000`), the access token drops both claims and adds `roles_pruned_chars` with the removed character count.
The introspection endpoint reconstructs the full role claims for introspection responses.

The changelog does not clearly identify the first released version of roles pruning, so this documentation does not pin
an introduction version.

### Introspection endpoint audience check

Use `mockserver.introspection-endpoint-audience-check` to control whether the introspection endpoint verifies that the
introspecting client's `client_id` is present in the token `aud` claim.

Modes:

- `off` (default): no audience enforcement; introspection stays active
- `warn`: validate and log a warning if `client_id` is missing from `aud`, but keep `active=true`
- `on`: enforce validation; if `client_id` is missing from `aud` (or cannot be resolved), return `active=false`

Set `oauth-mock-data.clients[].introspection-endpoint-audience-check` to override the server-wide mode for one client.

## `oauth-mock-data.users[]`

Each entry defines a selectable user for the login form.

| Property | Type | Required | Meaning |
|---|---|---:|---|
| `id` | string | yes | Login-form user id and in-memory username |
| `given-name` | string | no | Default `given_name`; default `Henriette` |
| `family-name` | string | no | Default `family_name`; default `Muster` |
| `email` | string | no | Email claim; default `henriette@muster.domain` |
| `locale` | string | no | Locale claim; default `DE` |
| `preferred-username` | string | no | Preferred username; default `1234` |
| `ext-id` | string | no | Value for the `ext_id` claim; default `5678` |
| `admin-dir-uid` | string | no | Value for the `admin_dir_uid` claim; default `U11111111` |
| `login-level` | string | no | Value for the `login` claim; default `S0` |
| `subject` | string | no | Explicit subject if you do not want to derive it from `preferred-username` |
| `userroles` | list of strings | no | Default user roles preselected in the login form |
| `bproles` | map string to list of strings | no | Default business-partner roles preselected in the login form |
| `additional-claims` | map string to arbitrary JSON values | no | Additional claims copied into issued tokens |

User data is only used for interactive logins. During the login flow, the form can override the configured default role
selection for the chosen user.

## Subject selection

For both the default jEAP mapper and the eIAM mapper, subject selection works like this:

1. user `preferred-username`, if present during a user login
2. otherwise user `subject`, if present during a user login
3. otherwise client `subject`, if configured
4. otherwise a random UUID

## Related topics

- [Getting started](getting-started.md)
- [Custom token claims](custom-token-claims.md)
- [Client integration examples](client-integration-examples.md)
