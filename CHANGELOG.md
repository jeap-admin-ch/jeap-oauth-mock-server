# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] - 2025-02-13

### Changed

- Update parent from 26.23.0 to 26.24.2
- Disable license plugins for service instances

## [3.1.0] - 2025-02-10

### Changed

- Update parent from 26.22.3 to 26.23.0
- Publish to maven central

## [3.0.0] - 2025-01-31

### Changed

- Prepare repository for Open Source distribution
- Remove static keystore and generate a key at startup to avoid storing sensitive information in the repository
  - The properties `mockserver.jwt*` have been removed
  - If you require the generated key pair in custom code based on the mockserver, you can simply inject the KeyPair as a
    Spring bean

## [2.33.0] - 2024-01-15

### Changed
- Switched to a multi-module project and added the module jeap-oauth-mock-server-instance which will instantiate a mock server instance when used as parent project.
- Updated parent to 26.22.3

## [2.32.0] - 2024-12-19

### Changed

- Update parent to 26.21.1

## [2.31.2] - 2024-12-17

### Changed

- Add "alg" key in JWKS endpoint
- Update parent to 26.20.0

## [2.31.1] - 2024-11-01

### Changed

- Provide the favicon in html template

## [2.31.0] - 2024-10-31

### Changed

- Update parent from 26.4.0 to 26.5.0

## [2.30.0] - 2024-10-25

### Changed

- Updated matching logic to support exact and wildcard matching for redirect URIs
 
## [2.29.0] - 2024-10-17

### Changed

- Update parent from 26.3.0 to 26.4.0

## [2.28.0] - 2024-09-20

### Changed

- Update parent from 26.0.0 to 26.3.0

## [2.27.0] - 2024-09-06

### Changed

- Update parent from 25.4.0 to 26.0.0

## [2.26.0] - 2024-08-22

### Changed

- Update parent from 24.5.0 to 25.4.0

## [2.25.0] - 2024-07-17

### Changed

- Add x.509 claims (x5c, x5t, x5t#S256) to jwks endpoint

## [2.24.0] - 2024-07-16

### Changed

- Update parent from 23.15.0 to 24.5.0

## [2.23.0] - 2024-04-18

### Changed

- Updated parent from 23.12.0 to 23.15.0
- Added support for dynamic scopes

## [2.22.0] - 2024-03-28

### Changed

- Update parent from 23.10.4 to 23.12.0

## [2.21.0] - 2024-03-14

### Changed

- Update parent from 23.6.1 to 23.10.4

## [2.20.0] - 2024-02-27

### Changed
 
- Updated parent from 23.0.0 to 23.6.1
- Removed webflux test dependency

## [2.19.0] - 2024-02-05

### Changed

- Update parent from 22.5.0 to 23.0.0

## [2.18.0] - 2024-01-25

### Changed

- Update parent from 22.4.0 to 22.5.0

## [2.17.0] - 2024-01-25

### Changed

- Update parent from 22.2.3 to 22.4.0

## [2.16.0] - 2024-01-23

### Changed

- Update parent from 22.2.2 to 22.2.3

## [2.15.0] - 2024-01-23

### Changed

- Update parent from 22.1.0 to 22.2.2

## [2.14.0] - 2024-01-16

### Changed

- Update parent from 22.0.0 to 22.1.0

## [2.13.0] - 2024-01-09

### Changed

- Update parent from 21.2.0 to 22.0.0

## [2.12.0] - 2024-01-03

### Changed

- EiamJwtAccessTokenCustomizer is now public so it can be used by other projects

## [2.11.0] - 2023-12-21

### Added

- JEAP-4134: Support for additional User Claims. They can be configured within the configuration properties under "additional-claims". E.g. "acr" in EIAM Token. 

## [2.10.0] - 2023-12-14

### Changed

- Update parent from 21.0.0 to 21.2.0 (spring boot 3.2)

## [2.9.0] - 2023-11-22

### Changed

- Update parent from 20.10.1 to 21.0.0

## [2.8.0] - 2023-11-09

### Changed

- Upgraded jeap-spring-boot-parent to version 20.10.1 and spring-security-oauth2-authorization-server to version 1.1.3.

## [2.7.1] - 2023-08-24

### Added

- Add id to submit button in login form

## [2.7.0] - 2023-08-16

### Changed

- Upgraded to spring boot 3.1 and spring-security-oauth2-authorization-server version 1.1.1

## [2.6.0] - 2023-08-09

### Changed

- Update parent from 19.16.1 to 19.17.0

## [2.5.0] - 2023-08-08

### Changed

- Update parent from 19.10.1 to 19.16.1

## [2.4.1 - 2023/05/23]

### Fixed

- JEAP-3642: redirect after logout will now end up on an logout page instead of "Whitelabel Error Page" 

## [2.4.0 - 2023/04/24]

### Changed

- Set token validity to 1 hour (instead 5 minutes)
- Upgraded jeap-spring-boot-parent from 19.9.0 to 19.10.1

## [2.3.0 - 2023/04/17]

### Changed

- Added admin_dir_uid claim to user information and login form.
- Upgraded jeap-spring-boot-parent from 19.8.0 to 19.9.0 to have support for admin_dir_uid claim.

## [2.2.5 - 2023/03/30]

### Changed

- Log helpful error message if the redirect URI does not match for a client

## [2.2.4 - 2023/03/29]

### Changed

- Add keycloak-/jeap-starter-compatible JWK cert endpoint without redirect

## [2.2.3 - 2023/03/28]

### Changed

- Add keycloak-/jeap-starter-compatible JWK cert endpoint redirect

## [2.2.2 - 2023/03/21]

### Changed

- Add email field to user data / login form

## [2.2.1 - 2023/02/21]

### Changed

- Return userroles/bproles claims in userinfo endpoint

## [2.2.0 - 2023/01/26]

### Changed

- Added B2B to AuthContext
- If no context is defined for a configured client, accept all AuthorizationGrantTypes and AuthenticationMethods.
  Otherwise, use the predefined AuthorizationGrantTypes and AuthenticationMethods defined in the enum AuthContext.

## [2.1.1 - 2023/01/19]

### Changed

- Added CLIENT_SECRET_POST to AuthContext USER for Swagger

## [2.1.0 - 2022/11/29]

### Changed

- Added option to provide a custom token format bean

## [2.0.0 - 2022/11/28]

### Changed

- Upgrade dependencies, change server framework to Spring Authorization Server

## [1.6.1 - 2022/10/11]

### Changed

- Set user SecurityFilterChain bean to the same order as the deprecated WebSecurityConfigurerAdapter was before.

## [1.6.0 - 2022/10/06]

### Changed

- Upgraded to jeap parent 18.0.0.

## [1.5.3 - 2022/06/20]

### Changed

- Add header to allow for silent refresh to work

## [1.5.2 - 2021/07/05]

### Changed

- Load bootstrap.css locally

## [1.5.1 - 2021/06/04]

### Changed

- Updated to spring-boot-parent 14.0.3

## [1.5.0 - 2021/06/01]

### Changed

- Updated to spring-boot-parent 14.0.0

## [1.4.5 - 2020/11/25]

### Changed

- Fixed duplicated source plugin

## [1.4.4 - 2020/11/25]

### Changed

- Updated to latest parent, including Javadoc and Source generation

## [1.4.3 - 2020/11/05]

### Changed

- Sort BP IDs by number / alphabetically

## [1.4.2 - 2020/11/05]

### Changed

- Fix broken mock server login when using angular-oidc-client after adding Id token due to missing sub in user info
- Fix BP roles configured in client section not offered in login form

## [1.4.1 - 2020/11/04]

### Changed

- see JEAP-1717 npe bugfix, if no user role is set for a user

## [1.4.0 - 2020/10/28]

### Changed

- see JEAP-1717 selectable users

## [1.3.1 - 2020/09/21]

### Changed

- First release using new build pipeline - no changes

## [1.3.0 - 2020/09/21]

### Added

- Returning an ID-Token

## [1.2.0 - 2020/08/06]

### Added

- Serving JWK certificates under /protocol/openid-connect/certs, tuhus eliminating the need for configuring a JWKS
  endpoint whn using the mock server

### Changed

- Updated to latest parent project and spring boot 2.3

## [1.1.3 - 2020/06/16]

### Added

- Updated to latest jEAP parent

## [1.1.2 - 2020/06/02]

### Added

- Include monitoring starter to expose actuator endpoints

## [1.1.1 - 2020/06/02]

### Fixed

- If specified by the user, set the PAMS id from the login page also as subject of the token and not just as
  preferred_username.

## [1.1.0 - 2020/04/24]

### Added

Extended Token with:

- extId
- loginLevel

## [1.0.0 - 2020/02/10]

### Changed

- Remove Static Reference in login.html

## [1.0.0 - 2020/02/10]

### Added

- Initial Version
