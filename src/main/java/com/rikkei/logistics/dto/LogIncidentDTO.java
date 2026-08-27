package com.rikkei.logistics.dto;

import java.util.regex.Pattern;

public record LogIncidentDTO(
        String timestamp,
        String serviceName,
        String hubCode,
        String trackingCode,
        String maskedCustomer,
        String errorMessage
) {
    private static final Pattern TRACKING =
            Pattern.compile("^RK-\\d{4}-\\d{3}$");

    private static final Pattern PHONE =
            Pattern.compile("(0\\d{2})(\\d{4})(\\d{3})");

    public LogIncidentDTO {
        if (trackingCode != null && !trackingCode.isBlank()
                && !TRACKING.matcher(trackingCode).matches()) {
            throw new IllegalArgumentException(
                    "Mã vận đơn không đúng định dạng RK-\\d{4}-\\d{3}: " + trackingCode);
        }
    }

    public static String maskCustomer(String fullName, String phone) {
        return maskName(fullName) + " (" + maskPhone(phone) + ")";
    }

    public static String maskCustomerRaw(String customerBlob) {
        if (customerBlob == null || customerBlob.isBlank()) {
            return "***";
        }
        String s = customerBlob.trim();
        int open = s.lastIndexOf('(');
        int close = s.lastIndexOf(')');
        if (open > 0 && close > open) {
            String name = s.substring(0, open).trim();
            String phone = s.substring(open + 1, close).trim();
            return maskCustomer(name, phone);
        }
        return maskName(s);
    }

    static String maskPhone(String phone) {
        if (phone == null) return "****";
        String digits = phone.replaceAll("\\D", "");
        var m = PHONE.matcher(digits);
        if (m.matches()) {
            return m.group(1) + "****" + m.group(3);
        }
        if (digits.length() >= 7) {
            return digits.substring(0, 3) + "****" + digits.substring(digits.length() - 3);
        }
        return "****";
    }

    static String maskName(String fullName) {
        if (fullName == null || fullName.isBlank()) return "***";
        String[] parts = fullName.trim().split("\\s+");
        if (parts.length == 1) {
            return parts[0].substring(0, 1).toUpperCase() + "***";
        }
        String first = parts[0].substring(0, 1).toUpperCase() + "***";
        String last = parts[parts.length - 1].substring(0, 1).toUpperCase() + "***";
        return first + " " + last;
    }
}
