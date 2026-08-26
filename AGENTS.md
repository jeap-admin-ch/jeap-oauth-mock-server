# AGENTS.md

Guidance for AI coding agents working **in this repository**. For how to *use* the mock server in a consuming
project, read [README.md](README.md) and the [docs/](docs/) folder instead.

## Project

jEAP OAuth Mock Server is a small multi-module Maven project built on Spring Security Authorization Server. It
provides a reusable OAuth2 / OpenID Connect mock server for local development, manual testing, and automated tests,
including a custom login form for authorization-code flows, configurable jEAP-style role claims, dynamic `bproles:*`
scopes, token introspection, and a token-customizer extension point.

## Repository layout

```text
pom.xml                                          # Parent POM (packaging=pom); declares the modules below
jeap-oauth-mock-server/                          # Library/application module
  src/main/java/ch/admin/bit/jeap/oauth/mock/server/
    ServerApplication.java                       # Spring Boot entry point
    config/                                      # OAuthMockData, ClientData, AuthContext, MockServerConfig
    security/                                    # SecurityConfig, patched client repository, introspection provider
    login/                                       # Custom login controller, login details, session-reset filter
    token/                                       # Default/eIAM token customizers, dynamic scope, roles pruning, claims
  src/main/resources/                            # local-test profile, templates, static assets
  src/test/java/                                 # integration and unit tests for auth flows, claims, headers, CSP
jeap-oauth-mock-server-instance/                 # POM-only parent for downstream mock-server instances
Jenkinsfile, publiccode.yml, CHANGELOG.md, LICENSE, setPomVersions.sh
```

## Build & test

```bash
./mvnw -pl jeap-oauth-mock-server -am install    # build the module and its dependencies
./mvnw verify                                    # full build incl. tests
./mvnw -pl jeap-oauth-mock-server test           # tests for the main module
```

- Parent: `ch.admin.bit.jeap:jeap-spring-boot-parent`.
- The Jenkins pipeline runs integration tests and quality checks on feature and master branches.
- Public behaviour changes should keep the auth-flow integration tests passing, especially for login, token issuance,
  introspection, and JWK/OpenID endpoints.

## jEAP conventions

- Java packages live under `ch.admin.bit.jeap.oauth.mock.server...`.
- Configuration properties use the prefixes `oauth-mock-data.*` and `mockserver.base-url`.
- New claim-mapping behaviour should usually be added via an `OAuth2TokenCustomizer<JwtEncodingContext>` bean by
  extending `AbstractJwtTokenCustomizer`, rather than by modifying `SecurityConfig` directly.
- `PamsJwtTokenCustomizer` is the default mapper, but `SecurityConfig` only registers it when no custom
  `OAuth2TokenCustomizer<JwtEncodingContext>` bean exists.
- Dynamic `bproles:*` scope support and non-standard registered-client behaviour are implemented by local patches around
  Spring Authorization Server classes; preserve those patches when upgrading dependencies.

## Docs

When changing public behaviour, update the matching focused file under [docs/](docs/) (one topic per file) and the
documentation index in the README.

- Pages must be valid MDX (Docusaurus renders every `.md` as MDX) and any Mermaid diagrams must use correct
  Mermaid syntax — see the [writing principles](https://github.com/jeap-admin-ch/jeap/blob/master/docs/documenting-jeap.md#writing-principles).
  There is no standalone linter for this; validate by actually building the docs site locally against this
  checkout, using the [site repository](https://github.com/jeap-admin-ch/jeap-admin-ch.github.io)'s
  `preview.sh --local <path-to-this-repo> --no-autodiscover` (production build, catches MDX/Mermaid syntax errors
  and broken links) or `dev.sh` for a faster hot-reload check.

## Versioning

- Semantic Versioning; all changes documented in [CHANGELOG.md](./CHANGELOG.md) (Keep a Changelog format).
- `setPomVersions.sh` updates the version across all module POMs.
- When working on a feature branch, increase the version to `x.y.z-SNAPSHOT` in the POMs.
- Always keep the -SNAPSHOT postfix in the POMs, CI will remove it when releasing a version. Do not use the
  SNAPSHOT postfix in other places (CHANGELOG, publiccode.yml etc.)
- Keep changelog entries concise and to the point, follow existing patterns.
- Keep commit messages short, use the JIRA ID from the branch name as a prefix, do not use conventional commits
  (for example: "JEAP-1234 Added feature X").
- When bumping the version, also update the changelog, and update version/date in `publiccode.yml`.
- When the version on a feature branch has not yet been bumped compared to master, ask the user if a major, minor
  or patch version bump should be performed, and update the version accordingly.
