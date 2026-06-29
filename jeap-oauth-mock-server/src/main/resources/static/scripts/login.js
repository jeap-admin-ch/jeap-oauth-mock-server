// Navigate to the login form for the selected user. Kept in an external file
// served from 'self' so it complies with the Content-Security-Policy
// (script-src 'self') applied by jeap-spring-boot-web-config-starter, which
// forbids inline event handlers.
document.addEventListener('DOMContentLoaded', function () {
    const usernameSelect = document.getElementById('username');
    if (usernameSelect) {
        usernameSelect.addEventListener('change', function () {
            globalThis.location = 'openIdMockServerLogin?user=' + this.value;
        });
    }
});
