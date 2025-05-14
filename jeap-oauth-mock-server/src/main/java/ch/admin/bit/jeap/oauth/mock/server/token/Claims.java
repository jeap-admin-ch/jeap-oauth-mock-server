package ch.admin.bit.jeap.oauth.mock.server.token;

public enum Claims {
    CONTEXT("ctx"),
    USERROLES("userroles"),
    BPROLES("bproles"),
    EXT_ID("ext_id"),
    ADMIN_DIR_UID("admin_dir_uid"),
    LOGIN("login_level"),
    ROLES_PRUNED_CHARS_CLAIM_NAME("roles_pruned_chars");

    private final String claim;

    Claims(String claim) {
        this.claim = claim;
    }

    public String claim() {
        return claim;
    }
}