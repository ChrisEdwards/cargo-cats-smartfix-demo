package com.contrast.frontgateservice.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityConfigSecurityTest {

    @Test
    void passwordEncoderShouldUseBCrypt() {
        SecurityConfig config = new SecurityConfig();
        PasswordEncoder encoder = config.passwordEncoder();

        assertNotNull(encoder, "PasswordEncoder bean must not be null");
        assertTrue(encoder instanceof BCryptPasswordEncoder,
                "PasswordEncoder must be BCryptPasswordEncoder, not a weak algorithm like MD5");
    }

    @Test
    void passwordEncoderShouldNotProduceMD5Hashes() {
        SecurityConfig config = new SecurityConfig();
        PasswordEncoder encoder = config.passwordEncoder();

        String encoded = encoder.encode("testPassword");
        assertNotNull(encoded, "Encoded password must not be null");
        assertTrue(encoded.startsWith("$2a$") || encoded.startsWith("$2b$") || encoded.startsWith("$2y$"),
                "Encoded password must use BCrypt format, got: " + encoded);
        assertFalse(encoded.matches("^[a-f0-9]{32}$"),
                "Encoded password must not be an MD5 hash");
    }
}
