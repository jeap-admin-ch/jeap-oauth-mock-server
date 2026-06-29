// Go back to the previous page. Kept in an external file served from 'self' so
// it complies with the Content-Security-Policy (script-src 'self') applied by
// jeap-spring-boot-web-config-starter, which forbids inline "javascript:" URIs.
document.addEventListener('DOMContentLoaded', function () {
    const backLink = document.getElementById('back-link');
    if (backLink) {
        backLink.addEventListener('click', function (event) {
            event.preventDefault();
            globalThis.history.back();
        });
    }
});
