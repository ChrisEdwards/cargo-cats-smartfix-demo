package com.contrast.frontgateservice.service;

import com.contrast.frontgateservice.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserServiceSecurityTest {

    private final SecurityConfig securityConfig = new SecurityConfig();

    @Test
    void passwordEncoder_usesBCrypt() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();
        assertNotNull(encoder, "PasswordEncoder bean must be configured");
        assertTrue(encoder instanceof BCryptPasswordEncoder,
                "PasswordEncoder must be BCryptPasswordEncoder, not MD5-based");
    }

    @Test
    void passwordEncoder_doesNotProduceMD5Hash() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();
        String encoded = encoder.encode("testPassword123");
        assertNotNull(encoded);
        assertTrue(encoded.startsWith("$2a$") || encoded.startsWith("$2b$") || encoded.startsWith("$2y$"),
                "Encoded password must use BCrypt format, got: " + encoded);
        assertFalse(encoded.matches("^[a-f0-9]{32}$"),
                "Encoded password must not be a raw MD5 hash");
    }

    @Test
    void passwordEncoder_verifiesEncodedPassword() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();
        String rawPassword = "securePassword!";
        String encoded = encoder.encode(rawPassword);
        assertTrue(encoder.matches(rawPassword, encoded),
                "PasswordEncoder must correctly verify encoded passwords");
    }
}
