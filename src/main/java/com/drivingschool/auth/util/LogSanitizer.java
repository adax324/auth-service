package com.drivingschool.auth.util;

import java.util.regex.Pattern;

public final class LogSanitizer {

    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\p{Cntrl}]");

    private LogSanitizer() {
    }

    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        return CONTROL_CHARS.matcher(value).replaceAll("_");
    }
}
