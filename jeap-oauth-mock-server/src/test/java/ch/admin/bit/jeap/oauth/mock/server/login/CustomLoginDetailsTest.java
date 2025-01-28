package ch.admin.bit.jeap.oauth.mock.server.login;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CustomLoginDetailsTest {

    @Test
    void fromRequest() {
        String locale = "DE";
        String given = "Given";
        String family = "Family";
        String email = "me@mail.com";
        String preferredUsername = "preferredUsername";
        String extId = "extId";
        String adminDirUID = "U11111111";
        String loginLevel = "logingLevel";

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("givenname", given);
        request.addParameter("familyname", family);
        request.addParameter("email", email);
        request.addParameter("locale", locale);
        request.addParameter("preferredusername", preferredUsername);
        request.addParameter("extid", extId);
        request.addParameter("admindiruid", adminDirUID);
        request.addParameter("loginlevel", loginLevel);
        request.addParameter("userroles", "u1", "u2");
        request.addParameter("additionaluserroles", "addn1 addn2");
        request.addParameter("bproles", "bp1", "bp2");
        request.addParameter("additionalbproles", "3:bp3 4:bp4_1 4:bp4_2");

        CustomLoginDetails customLoginDetails = CustomLoginDetails.fromRequest(request);

        assertEquals(given, customLoginDetails.getGivenName());
        assertEquals(family, customLoginDetails.getFamilyName());
        assertEquals(email, customLoginDetails.getEmail());
        assertEquals(locale, customLoginDetails.getLocale());
        assertEquals(preferredUsername, customLoginDetails.getPreferredUserName());
        assertEquals(extId, customLoginDetails.getExtId());
        assertEquals(adminDirUID, customLoginDetails.getAdminDirUID());
        assertEquals(loginLevel, customLoginDetails.getLoginLevel());
        assertEquals(asList("u1", "u2", "addn1", "addn2"), customLoginDetails.getUserRoles());
        assertEquals(asList("bp1", "bp2", "3:bp3", "4:bp4_1", "4:bp4_2"), customLoginDetails.getBpRoles());
    }
}
