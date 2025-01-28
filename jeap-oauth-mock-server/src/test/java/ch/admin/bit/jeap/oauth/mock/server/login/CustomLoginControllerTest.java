package ch.admin.bit.jeap.oauth.mock.server.login;

import ch.admin.bit.jeap.oauth.mock.server.config.ClientData;
import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData;
import org.apache.groovy.util.Maps;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Collections.emptyMap;
import static java.util.stream.Collectors.toMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CustomLoginControllerTest {

    private static final String BP_ROLE_A = "bp-role-a";
    private static final String BP_ROLE_B = "bp-role-b";
    private static final String BP_ROLE_C = "bp-role-c";

    private static final String USER_ROLE_A = "user-role-a";
    private static final String USER_ROLE_B = "user-role-b";
    private static final String USER_ROLE_C = "user-role-c";

    private static final String CLIENT_ROLE_A = "client-role-a";
    private static final String CLIENT_ID_A = "client-id-a";
    private static final String CLIENT_BP_ROLE_1 = "client-bp-role-1";
    private static final String CLIENT_BP_ROLE_2 = "client-bp-role-2";
    private static final String BP_CLIENT = "bp-client";

    private final static String BP_1 = "10000000";
    private final static String BP_2 = "10000001";

    private final ClientData clientData = new ClientData();

    @Test
    void testNoRoles() {
        CustomLoginController controller = createController(false, false, false);
        List<String> userRoles = getUserRoles(controller);

        assertEquals(0, userRoles.size());

        clientData.setBproles(emptyMap());
        RegisteredClient testClient = clientData.toRegisteredClient();

        Map<String, Set<String>> bpRoles = controller.transposeAvailableRoles(testClient);
        assertEquals(0, bpRoles.size());
    }

    @Test
    void testUserRole() {
        CustomLoginController controller = createController(false, true, false);

        List<String> userRoles = getUserRoles(controller);
        assertEquals(3, userRoles.size());
        assertTrue(userRoles.contains(USER_ROLE_A));
        assertTrue(userRoles.contains(USER_ROLE_B));
        assertTrue(userRoles.contains(USER_ROLE_C));

        clientData.setBproles(emptyMap());
        RegisteredClient testClient = clientData.toRegisteredClient();

        Map<String, Set<String>> bpRoles = controller.transposeAvailableRoles(testClient);

        assertEquals(0, bpRoles.size());
    }

    @Test
    void testBpRole() {
        CustomLoginController controller = createController(false, false, true);

        List<String> userRoles = getUserRoles(controller);
        assertEquals(0, userRoles.size());

        clientData.setBproles(emptyMap());
        RegisteredClient testClient = clientData.toRegisteredClient();

        Map<String, Set<String>> bpRoles = controller.transposeAvailableRoles(testClient);

        assertEquals(2, bpRoles.size());
        assertTrue(bpRoles.values().stream().anyMatch(roles -> roles.contains(BP_ROLE_A)));
        assertTrue(bpRoles.values().stream().anyMatch(roles -> roles.contains(BP_ROLE_B)));
        assertTrue(bpRoles.values().stream().anyMatch(roles -> roles.contains(BP_ROLE_C)));
    }

    @Test
    void testUserAndBpRole() {
        CustomLoginController controller = createController(false, true, true);

        List<String> userRoles = getUserRoles(controller);
        assertEquals(3, userRoles.size());

        clientData.setBproles(emptyMap());
        RegisteredClient testClient = clientData.toRegisteredClient();

        Map<String, Set<String>> bpRoles = controller.transposeAvailableRoles(testClient);
        assertEquals(2, bpRoles.size());
        assertTrue(bpRoles.values().stream().anyMatch(roles -> roles.contains(BP_ROLE_A)));
        assertTrue(bpRoles.values().stream().anyMatch(roles -> roles.contains(BP_ROLE_B)));
        assertTrue(bpRoles.values().stream().anyMatch(roles -> roles.contains(BP_ROLE_C)));
    }

    @Test
    void testClientAndUserRole() {
        CustomLoginController controller = createController(true, true, false);

        List<String> userRoles = getUserRoles(controller);
        assertEquals(4, userRoles.size());
        assertTrue(userRoles.contains(CLIENT_ROLE_A));
        assertTrue(userRoles.contains(USER_ROLE_A));
        assertTrue(userRoles.contains(USER_ROLE_B));
        assertTrue(userRoles.contains(USER_ROLE_C));

        clientData.setBproles(emptyMap());
        RegisteredClient testClient = clientData.toRegisteredClient();

        assertEquals(0, controller.transposeAvailableRoles(testClient).size());
    }

    @Test
    void testClientAndUserAndBpRole() {
        CustomLoginController controller = createController(true, true, true);

        List<String> userRoles = getUserRoles(controller);
        assertEquals(4, userRoles.size());

        Map<String, List<String>> clientRoles = Maps.of(BP_CLIENT, List.of(CLIENT_BP_ROLE_1, CLIENT_BP_ROLE_2));
        clientData.setBproles(clientRoles);
        RegisteredClient testClient = clientData.toRegisteredClient();
        Map<String, Set<String>> bpRoles = controller.transposeAvailableRoles(testClient);

        assertTrue(bpRoles.containsKey(BP_CLIENT));
        assertEquals(Set.of(CLIENT_BP_ROLE_1, CLIENT_BP_ROLE_2), bpRoles.get(BP_CLIENT));
        assertEquals(Set.of(BP_ROLE_A, BP_ROLE_B, BP_ROLE_C), bpRoles.get(BP_1));
        assertEquals(Set.of(BP_ROLE_A, BP_ROLE_C), bpRoles.get(BP_2));
        assertEquals(3, bpRoles.size());
    }

    @Test
    void testBpRoleSorting() {
        CustomLoginController controller = createController(true, true, true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        Model model = new ConcurrentModel();
        clientData.setBproles(Map.of(
                "99", List.of("2"),
                "abc", List.of("1")));

        controller.login(model, request);

        List<String> bpRoleList = getBpRoleList(model);
        List<String> bpIds = bpRoleList.stream()
                .map(id -> id.split(":")[0])
                .collect(Collectors.toList());
        assertEquals(
                List.of("10000000", "10000000", "10000000", "10000001", "10000001", "99", "abc"),
                bpIds);
    }

    @Test
    void testLogout() {
        CustomLoginController controller = createController(true, true, true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("logout", "");
        var result = controller.login(new ConcurrentModel(), request);
        assertEquals("logout", result.getViewName());
    }

    @SuppressWarnings("unchecked")
    private List<String> getBpRoleList(Model model) {
        List<String> bpRoleList = (List<String>) model.getAttribute("bpRoles");
        return Objects.requireNonNull(bpRoleList);
    }

    private CustomLoginController createController(boolean hasClientRole, boolean hasUserRoles, boolean hasBpRoles) {
        List<ClientData> clients = new ArrayList<>();
        clientData.setClientId("client-id-a");
        clients.add(clientData);
        if (hasClientRole) {
            clientData.setUserroles(List.of(CLIENT_ROLE_A));
        }

        List<OAuthMockData.UserData> users = List.of(
                OAuthMockData.UserData.builder()
                        .id("user-1")
                        .givenName("U")
                        .familyName("Ser1")
                        .locale("DE")
                        .preferredUsername("user-1")
                        .bproles(hasBpRoles ? Map.of(BP_1, List.of(BP_ROLE_A, BP_ROLE_B)) : Map.of())
                        .userroles(hasUserRoles ? List.of(USER_ROLE_A, USER_ROLE_B) : List.of())
                        .build(),
                OAuthMockData.UserData.builder()
                        .id("user-2")
                        .givenName("U")
                        .familyName("Ser2")
                        .locale("DE")
                        .preferredUsername("user-2")
                        .bproles(hasBpRoles ? Map.of(BP_1, List.of(BP_ROLE_A, BP_ROLE_C),
                                BP_2, List.of(BP_ROLE_A, BP_ROLE_C)) : Map.of())
                        .userroles(hasUserRoles ? List.of(USER_ROLE_B, USER_ROLE_C) : List.of())
                        .build());


        return new CustomLoginController(clients.stream()
                .collect(toMap(ClientData::getClientId, ClientData::toRegisteredClient)), users) {
            @Override
            RegisteredClient getClientFromSavedRequest(HttpServletRequest request) {
                return clientData.toRegisteredClient();
            }
        };
    }

    private List<String> getUserRoles(CustomLoginController controller) {
        RegisteredClient client = controller.getClientById(new String[]{CLIENT_ID_A});
        return controller.mergeClientWithUserRoles(client);
    }
}
