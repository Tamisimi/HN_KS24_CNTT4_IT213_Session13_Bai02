package com.rikkei.logistics;

import com.rikkei.logistics.dto.LogIncidentDTO;
import com.rikkei.logistics.security.LogisticsSecurityValidator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LogisticsSecurityTest {

    @Test
    void testCase1_sqlAnToan_themLimit100() {
        String input = "SELECT * FROM deliveries WHERE hub_code = 'HN-01'";
        String result = LogisticsSecurityValidator.validateSql(input);
        assertTrue(result.toUpperCase().contains("LIMIT 100"), result);
        System.out.println("PASS TC1 SQL an toàn => " + result);
    }

    @Test
    void testCase2_sqlDocHai_nemSecurityException() {
        String input = "SELECT * FROM deliveries; DROP TABLE deliveries;";
        SecurityException ex = assertThrows(SecurityException.class,
                () -> LogisticsSecurityValidator.validateSql(input));
        System.out.println("PASS TC2 SQL độc hại => " + ex.getMessage());
    }

    @Test
    void testCase3_pathTraversal_nemSecurityException() {
        String base = "C:/data/logistics/reports";
        String evil = "../../Windows/System32/config.sys";
        SecurityException ex = assertThrows(SecurityException.class,
                () -> LogisticsSecurityValidator.sanitizeReportPath(base, evil));
        System.out.println("PASS TC3 Path Traversal => " + ex.getMessage());
    }

    @Test
    void testCase4_piiMasking() {
        String masked = LogIncidentDTO.maskCustomer("Nguyen Van An", "0912345678");
        assertEquals("N*** A*** (091****678)", masked);
        System.out.println("PASS TC4 PII Masking => " + masked);

        var dto = new LogIncidentDTO(
                "2026-08-21 08:30:15",
                "sorting-hub-hn",
                "HN-01",
                "RK-2026-001",
                masked,
                "Delivery delayed"
        );
        assertEquals("RK-2026-001", dto.trackingCode());
    }
}
