package ch.admin.bit.jeap.oauth.mock.server.login;

import ch.admin.bit.jeap.oauth.mock.server.config.ClientData;
import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData.UserData;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Controller
public class CustomLoginController {

    public static final String LOGIN_FORM_PATH = "/openIdMockServerLogin"; //NOSONAR Deliberately kept as a fixed constant

    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final Map<String, RegisteredClient> clientsById;
    private final List<UserData> users;

    public CustomLoginController(Map<String, RegisteredClient> clientsById, List<UserData> users) {
        this.clientsById = clientsById;
        this.users = users;
    }

    @GetMapping(LOGIN_FORM_PATH)
    public ModelAndView login(Model model, HttpServletRequest request) {
        if (request.getParameterMap().containsKey("logout")) {
            return new ModelAndView("logout", model.asMap());
        }
        RegisteredClient client = requireClientFromOAuthRequest(request);

        UserData defaultUser = getUser(request.getParameter("user"));
        model.addAttribute("defaultUsername", defaultUser.getId());
        model.addAttribute("users", users);

        model.addAttribute("roles", mergeClientWithUserRoles(client));

        Map<String, Set<String>> bpRoles = transposeAvailableRoles(client);
        model.addAttribute("bpRoles", CustomLoginDetails.bpRolesAsFlatList(bpRoles));

        model.addAttribute("preSelectedUserRoles", defaultUser.getUserroles());
        model.addAttribute("preSelectedBpRoles", CustomLoginDetails.bpRolesAsFlatList(defaultUser.getBproles()));

        return new ModelAndView("login", model.asMap());
    }

    private UserData getUser(String userId) {
        return users.stream().filter(user -> user.getId().equals((userId != null && !userId.isEmpty()) ? userId : null))
                .findFirst().orElse(users.get(0));
    }

    List<String> mergeClientWithUserRoles(RegisteredClient client) {
        List<String> userRolesForClient = ClientData.getUserRolesForClient(client);
        List<String> clientRoles = userRolesForClient == null ? List.of() : userRolesForClient;

        return Stream.concat(clientRoles.stream(), users.stream().flatMap(user -> user.getUserroles().stream()))
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    /*
    Get all BP-roles for all the business partners.
    E.g.:
    User1:
    "10000001": ["role1"]
    "10000002": ["role1", "role2"]

    User2:
    "10000001": ["role2"]
    "10000003": ["role2"]

    will be transposed to:
    "10000001": ["role1", "role2"]
    "10000002": ["role1", "role2"]
    "10000003": ["role2"]
     */
    Map<String, Set<String>> transposeAvailableRoles(RegisteredClient client) {
        Map<String, Set<String>> bproles = new HashMap<>();
        Map<String, List<String>> businessPartnerRolesForClient = ClientData.getBusinessPartnerRolesForClient(client);
        if (businessPartnerRolesForClient != null) {
            businessPartnerRolesForClient.forEach((key, values) -> bproles.put(key, new TreeSet<>(values)));
        }
        users.forEach(user -> user.getBproles().keySet().forEach(bpid -> {
            // Check if bpid is already in map. If so, add roles to this key
            List<String> bpRolesForUser = user.getBproles().get(bpid);
            bproles.computeIfAbsent(bpid, id -> new TreeSet<>()).addAll(bpRolesForUser);
        }));
        return bproles;
    }

    private RegisteredClient requireClientFromOAuthRequest(HttpServletRequest request) {
        RegisteredClient clientData = getClientFromSavedRequest(request);
        if (clientData == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown or missing client ID");
        }
        return clientData;
    }

    RegisteredClient getClientFromSavedRequest(HttpServletRequest request) {
        SavedRequest oauthRequest = requestCache.getRequest(request, null);
        String[] clientIds = oauthRequest == null ? null : oauthRequest.getParameterValues("client_id");
        return getClientById(clientIds);
    }

    RegisteredClient getClientById(String[] clientIds) {
        if (clientIds != null && clientIds.length == 1) {
            String clientId = clientIds[0];
            return clientsById.get(clientId);
        }
        return null;
    }
}
