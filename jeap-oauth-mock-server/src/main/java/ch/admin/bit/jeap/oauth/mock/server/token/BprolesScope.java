package ch.admin.bit.jeap.oauth.mock.server.token;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
class BprolesScope {

    // match business partner in 'bproles' dynamic scope as group named 'value'
    private static final Pattern BUSINESS_PARTNER_SCOPE_VALUE_PATTERN =
            Pattern.compile("bproles:(?<value>\\S+)");
    private static final String ALL_BUSINESS_PARTNERS_VALUE = "*";

    private final String value;

    static BprolesScope from(String scope) {
        String value = extractBprolesScopeValue(scope);
        return value != null ? new BprolesScope(value) : null;
    }

    boolean includesAllPartners() {
        return ALL_BUSINESS_PARTNERS_VALUE.equals(value);
    }

    String getBusinessPartner() {
        if (!includesAllPartners()) {
            return value;
        } else {
            return null;
        }
    }

    private static String extractBprolesScopeValue(String scope) {
        if (scope == null) {
            return null;
        }
        Matcher businessPartnerMatcher = BUSINESS_PARTNER_SCOPE_VALUE_PATTERN.matcher(scope);
        if (businessPartnerMatcher.matches()) {
            return businessPartnerMatcher.group("value");
        } else {
            return null;
        }
    }

}
