package com.rikkei.logistics.security;

import java.nio.file.Path;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class LogisticsSecurityValidator {

    private static final Pattern LIMIT_PATTERN =
            Pattern.compile("\\blimit\\s+(\\d+)\\b", Pattern.CASE_INSENSITIVE);

    private static final String[] FORBIDDEN_SQL = {
            "drop", "delete", "update", "insert", "alter", "truncate", "--", ";"
    };

    private LogisticsSecurityValidator() {}

    public static String validateSql(String rawSql) {
        if (rawSql == null || rawSql.isBlank()) {
            throw new SecurityException("SQL rỗng không được phép");
        }

        String sql = rawSql.trim();
        String lower = sql.toLowerCase(Locale.ROOT);

        if (!lower.startsWith("select")) {
            throw new SecurityException("Chỉ cho phép câu lệnh SELECT");
        }

        for (String bad : FORBIDDEN_SQL) {
            if (lower.contains(bad)) {
                throw new SecurityException("Phát hiện từ khóa/ký tự nguy hiểm trong SQL: " + bad);
            }
        }

        Matcher m = LIMIT_PATTERN.matcher(sql);
        if (m.find()) {
            int n = Integer.parseInt(m.group(1));
            if (n > 100) {
                sql = m.replaceFirst("LIMIT 100");
            }
        } else {
            if (sql.endsWith(";")) {
                sql = sql.substring(0, sql.length() - 1).trim();
            }
            sql = sql + " LIMIT 100";
        }

        return sql;
    }

    public static Path sanitizeReportPath(String baseDir, String userFileName) {
        if (baseDir == null || baseDir.isBlank()) {
            throw new SecurityException("baseDir không hợp lệ");
        }
        if (userFileName == null || userFileName.isBlank()) {
            throw new SecurityException("Tên file không hợp lệ");
        }

        Path base = Path.of(baseDir).toAbsolutePath().normalize();
        Path resolved = base.resolve(userFileName.trim()).normalize();

        if (!resolved.startsWith(base)) {
            throw new SecurityException("Path Traversal bị chặn: " + userFileName);
        }

        return resolved;
    }
}
