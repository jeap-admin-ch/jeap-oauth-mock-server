package ch.admin.bit.jeap.oauth.mock.server.login;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Spring Login form support is stateful, i.e. a HTTP session is used to keep the current OAuth request while the user
 * fills the login form. This filter invalidates the session as soon as an auth code is generated after submitting
 * the login form, thus making sure the login form is displayed again when going through the mock auth server. This
 * allows the user to enter roles etc. in the login form without having to log out / clear the browser cache  beforehand.
 */
@Slf4j
public class ForceLoginFormFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        filterChain.doFilter(servletRequest, servletResponse);

        String redirectUrl = getRedirectUrl((HttpServletResponse) servletResponse);
        if (isTokenGrantRedirect(redirectUrl)) {
            invalidateSession((HttpServletRequest) servletRequest);
        }
    }

    private String getRedirectUrl(HttpServletResponse response) {
        if (response.getStatus() >= 300 && response.getStatus() < 400) {
            return response.getHeader(HttpHeaders.LOCATION);
        }
        return null;
    }

    private boolean isTokenGrantRedirect(String url) {
        return url != null && (url.contains("code=") || url.contains("error="));
    }

    private void invalidateSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            log.info("Login succeeded, clearing HTTP session");
            session.invalidate();
        }
    }
}