package ch.admin.bit.jeap.oauth.mock.server.token;

import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class JeapRolesPruningTokenMapper {

    private final int rolesPruningLimit;

    public JeapRolesPruningTokenMapper(OAuthMockData oAuthMockData) {
        this.rolesPruningLimit = oAuthMockData.getRolesPruningLimit();
        log.info("Configured rolesPruningLimit: {}", rolesPruningLimit);
    }

    @SuppressWarnings("unchecked")
    public void pruneRolesInClaimsIfNecessary(Map<String, Object> claims) {
        Map<String, List<String>> bpRoles = new HashMap<>();

        if (claims.get("bproles") instanceof Map) {
            bpRoles = (Map<String, List<String>>) claims.get("bproles");
        }

        List<String> userRoles = new ArrayList<>();

        if (claims.get("userroles") instanceof List) {
            userRoles = (List<String>) claims.get("userroles");
        }

        int bpRolesSize = calculateBpRolesSize(bpRoles);
        int userRolesSize = calculateUserRolesSize(userRoles);
        int rolesSize = bpRolesSize + userRolesSize;

        if (rolesSize > rolesPruningLimit) {
            // Roles will take up too much space in the token and must be pruned
            log.debug("The combined size of userRoles and bpRoles {} is greater than rolesPruningLimit {}: pruning roles in token", rolesSize, rolesPruningLimit);
            claims.remove(Claims.USERROLES.claim());
            claims.remove(Claims.BPROLES.claim());
            claims.put(Claims.ROLES_PRUNED_CHARS_CLAIM_NAME.claim(), rolesSize);
        }
    }

    private int calculateBpRolesSize(Map<String, List<String>> bpRoles) {
        if (bpRoles.isEmpty()) {
            return 0;
        }
        int size = 12; // "bproles":{}
        for (var entry : bpRoles.entrySet()) {
            size += entry.getKey().length() + 5; // "..":[..]
            size += calculateRoleListSize(entry.getValue());
        }
        if (bpRoles.size() > 1) {
            size += bpRoles.size()-1; // commas
        }
        return size;
    }

    private int calculateUserRolesSize(List<String> userRoles) {
        if (userRoles.isEmpty()) {
            return 0;
        }
        int size = 14; // "userroles":[]
        size += calculateRoleListSize(userRoles);
        return size;
    }

    private int calculateRoleListSize(List<String> roles) {
        int size = 0;
        for (String role : roles) {
            if (role != null) {
                size += role.length() + 2; // "role"
            }
        }
        if (roles.size() > 1) {
            size += roles.size()-1; // commas
        }
        return size;
    }

}
