package com.contrast.frontgateservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class UserServiceSecurityTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void passwordEncoderShouldUseBCrypt() {
        assertNotNull(passwordEncoder, "PasswordEncoder bean must be present");
        assertTrue(passwordEncoder instanceof BCryptPasswordEncoder,
                "PasswordEncoder must be BCryptPasswordEncoder, not MD5-based");
    }

    @Test
    void encodedPasswordShouldNotUseMD5Format() {
        String encoded = passwordEncoder.encode("testPassword123");
        assertNotNull(encoded, "Encoded password must not be null");
        assertTrue(encoded.startsWith("$2a$") || encoded.startsWith("$2b$") || encoded.startsWith("$2y$"),
                "Encoded password must use BCrypt format (starting with $2a$, $2b$, or $2y$)");
    }

    @Test
    void encodedPasswordShouldNotMatchMD5Pattern() {
        String encoded = passwordEncoder.encode("password");
        assertFalse(encoded.matches("\\{[^}]*\\}[a-f0-9]{32}"),
                "Encoded password must not match MD5 hash pattern");
    }
}
