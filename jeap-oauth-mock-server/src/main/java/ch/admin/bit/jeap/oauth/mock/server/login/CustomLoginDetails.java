package ch.admin.bit.jeap.oauth.mock.server.login;

import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.*;
import static org.springframework.util.StringUtils.hasText;

@Getter
@EqualsAndHashCode(callSuper = true)
public class CustomLoginDetails extends WebAuthenticationDetails {
    private static final String BP_ROLE_SEPARATOR = ":";
    private static final String LIST_TEXTFIELD_SEPARATOR = "[\\s,]+";
    private final String givenName;
    private final String familyName;
    private final String email;
    private final String locale;
    private final String preferredUserName;
    private final String extId;
    private final String adminDirUID;
    private final String loginLevel;
    private final List<String> userRoles;
    private final List<String> bpRoles;

    public static CustomLoginDetails fromRequest(HttpServletRequest request) {
        String givenName = request.getParameter("givenname");
        String familyName = request.getParameter("familyname");
        String email = request.getParameter("email");
        String locale = request.getParameter("locale");
        String preferredUsername = request.getParameter("preferredusername");
        String extId = request.getParameter("extid");
        String adminDirUID = request.getParameter("admindiruid");
        String loginLevel = request.getParameter("loginlevel");
        String[] userroles = request.getParameterValues("userroles");
        String additionaluserroles = request.getParameter("additionaluserroles");
        String[] bproles = request.getParameterValues("bproles");
        String additionalbproles = request.getParameter("additionalbproles");

        return new CustomLoginDetails(request, givenName, familyName, email, locale, preferredUsername, extId,
                adminDirUID, loginLevel, userroles, additionaluserroles, bproles, additionalbproles);
    }

    CustomLoginDetails(HttpServletRequest request, String givenName, String familyName, String email, String locale,
                       String preferredUserName, String extId, String adminDirUID, String loginLevel, String[] userRoles,
                       String additionalUserRoles, String[] bpRoles, String additionalBpRoles) {
        super(request);
        this.givenName = givenName;
        this.familyName = familyName;
        this.email = email;
        this.locale = locale;
        this.preferredUserName = preferredUserName;
        this.extId = extId;
        this.adminDirUID = adminDirUID;
        this.loginLevel = loginLevel;

        this.userRoles = userRoles == null ? new ArrayList<>() : new ArrayList<>(asList(userRoles));
        if (hasText(additionalUserRoles)) {
            this.userRoles.addAll(asList(additionalUserRoles.split(LIST_TEXTFIELD_SEPARATOR)));
        }

        this.bpRoles = bpRoles == null ? new ArrayList<>() : new ArrayList<>(asList(bpRoles));
        this.bpRoles.addAll(asList(additionalBpRoles.split(LIST_TEXTFIELD_SEPARATOR)));
    }

    public OAuthMockData.UserData toUserDataWithDefaults(OAuthMockData.UserData userDataDefaults) {
        OAuthMockData.UserData.UserDataBuilder userDataBuilder = userDataDefaults.toBuilder();

        if (hasText(familyName)) {
            userDataBuilder.familyName(familyName);
        }
        if (hasText(givenName)) {
            userDataBuilder.givenName(givenName);
        }
        if (hasText(email)) {
            userDataBuilder.email(email);
        }
        if (hasText(locale)) {
            userDataBuilder.locale(locale);
        }
        if (hasText(preferredUserName)) {
            userDataBuilder.preferredUsername(preferredUserName);
        }
        if (hasText(extId)) {
            userDataBuilder.extId(extId);
        }
        if(hasText(adminDirUID)) {
            userDataBuilder.adminDirUID(adminDirUID);
        }

        if (hasText(loginLevel)) {
            userDataBuilder.loginLevel(loginLevel);
        }

        userDataBuilder.userroles(this.userRoles);
        userDataBuilder.bproles(bpRolesFromFlatList(bpRoles));

        return userDataBuilder.build();
    }

    /**
     * Converts business partner roles to a flat list of strings in the form bpid:role1, bpid:role2...,
     * suitable to use as a list of checkboxes to present to the user.
     */
    static List<String> bpRolesAsFlatList(Map<String, ? extends Collection<String>> bpRoles) {
        if (bpRoles == null) {
            return emptyList();
        }
        return bpRoles.entrySet().stream()
                .flatMap(entry -> entry.getValue().stream().map(bpRole -> entry.getKey() + BP_ROLE_SEPARATOR + bpRole))
                .distinct()
                .sorted()
                .collect(toList());
    }

    private static Map<String, List<String>> bpRolesFromFlatList(List<String> bpRoles) {
        return bpRoles.stream()
                .map(role -> role.split(BP_ROLE_SEPARATOR))
                .filter(rolePerPartner -> rolePerPartner.length == 2)
                .collect(groupingBy(
                        CustomLoginDetails::extractBusinessPartner,
                        mapping(CustomLoginDetails::extractBusinessPartnerRole, toList())));
    }

    private static String extractBusinessPartner(String[] role) {
        return role[0];
    }

    private static String extractBusinessPartnerRole(String[] role) {
        return role[1];
    }
}
