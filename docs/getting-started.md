# Getting started

This repository provides a configurable OAuth2 / OpenID Connect mock server for local development, manual testing,
and test environments. It can issue tokens for service-to-service calls and interactive UI logins, including jEAP-style
`userroles` and `bproles` claims.

Use it only for non-production scenarios. It allows issuing tokens for arbitrary configured users and roles and does not
provide real user authentication.

## Choose an integration style

You can create your own mock-server application in two ways:

- **Use `jeap-oauth-mock-server-instance` as Maven parent** when you want a dedicated mock-server project with minimal
  setup.
- **Depend on `jeap-oauth-mock-server` directly** when you already have a multi-module build and want to add a mock
  server module to it.

The published artifacts use group id `ch.admin.bit.jeap`.

## Create a dedicated mock-server instance

Use the instance parent POM for a minimal service instance:

```xml
<parent>
  <groupId>ch.admin.bit.jeap</groupId>
  <artifactId>jeap-oauth-mock-server-instance</artifactId>
  <version>10.1.0</version>
</parent>
```

The instance parent has packaging `pom` and already adds a dependency on `jeap-oauth-mock-server`.
It is intended for downstream projects that contribute their own application class and configuration.

## Add the library to an existing module

If you already have an application module, add the library dependency directly:

```xml
<dependency>
  <groupId>ch.admin.bit.jeap</groupId>
  <artifactId>jeap-oauth-mock-server</artifactId>
</dependency>
```

## Configure clients and users

Configure the mock data under the `oauth-mock-data` prefix.

```yaml
oauth-mock-data:
  clients:
    - client-id: "example-ui"
      registered-redirect-uri:
        - "http://localhost:4200/startpage"
      context: "USER"
      audience: [ "example-resource" ]
      scope: [ "openid" ]
      userroles: [ "partners-list", "partner-read", "partner-write" ]
      bproles:
        "12345": [ "partner-read" ]
        "67890": [ "partner-read", "partner-write" ]

    - client-id: "example-service"
      client-secret: "{noop}secret"
      context: "SYS"
      audience: [ "example-resource" ]
      userroles: [ "partner-read" ]
      bproles:
        "12345": [ "partner-read" ]

  users:
    - id: "user"
      given-name: "Henriette"
      family-name: "Muster"
      locale: "DE"
      preferred-username: "12345"
      ext-id: "1123"
      admin-dir-uid: "U12345678"
      login-level: "S3"
      userroles: [ "partners-list" ]
      bproles:
        "12345": [ "partner-read" ]
        "67890": [ "partner-read" ]
      additional-claims:
        acr: "urn:example:loa:substantial"
```

For the complete property reference, see [Configuration](configuration.md).

## Run locally

The library ships with a `local-test` profile example. In a mock-server application, start the server with that profile.
The built-in example configuration uses:

- Base URL: `http://localhost:8180/jeap-oauth-mock-server`
- Login form path: `/openIdMockServerLogin`
- Preconfigured users: `user`, `another-user`

A typical local run command is:

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=local-test
```

## Start the login form via an authorization request

The login form cannot be opened directly. It only works when an OAuth authorization request has first been stored in
the HTTP session.

To reach it, initiate an authorization-code flow first:

```text
http://localhost:8180/jeap-oauth-mock-server/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://redirect&scope=openid&code_challenge=JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0&code_challenge_method=S256
```

Spring Security redirects unauthenticated requests to `/openIdMockServerLogin`, where you can select the configured
user and override roles for that test case.

The server requires PKCE with S256. The example challenge above was derived from the verifier `test-verifier`.

## Next steps

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [Custom token claims](custom-token-claims.md)
- [Client integration examples](client-integration-examples.md)
