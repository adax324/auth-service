package com.drivingschool.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private FilterChain filterChain;

    private JwtAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter(jwtUtils);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("should set authentication when valid Bearer token is present")
    void validToken_shouldSetAuthentication() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer valid.jwt.token");
        when(jwtUtils.validateJwtToken("valid.jwt.token")).thenReturn(true);
        when(jwtUtils.getUserNameFromJwtToken("valid.jwt.token")).thenReturn("testuser");

        filter.doFilterInternal(request, response, filterChain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("testuser", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should not set authentication when token is invalid")
    void invalidToken_shouldNotSetAuthentication() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer invalid.token");
        when(jwtUtils.validateJwtToken("invalid.token")).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should not set authentication when no Authorization header")
    void noHeader_shouldNotSetAuthentication() throws ServletException, IOException {
        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should not set authentication when Authorization header has no Bearer prefix")
    void noBearerPrefix_shouldNotSetAuthentication() throws ServletException, IOException {
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should always call filterChain even when exception occurs")
    void exceptionInValidation_shouldStillCallFilterChain() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer some.token");
        when(jwtUtils.validateJwtToken("some.token")).thenThrow(new RuntimeException("unexpected"));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should extract token correctly from Bearer header")
    void shouldExtractTokenCorrectly() throws ServletException, IOException {
        String token = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0In0.sig";
        request.addHeader("Authorization", "Bearer " + token);
        when(jwtUtils.validateJwtToken(token)).thenReturn(true);
        when(jwtUtils.getUserNameFromJwtToken(token)).thenReturn("test");

        filter.doFilterInternal(request, response, filterChain);

        verify(jwtUtils).validateJwtToken(token);
        verify(jwtUtils).getUserNameFromJwtToken(token);
    }

    @Test
    @DisplayName("should set empty authorities in authentication")
    void shouldSetEmptyAuthorities() throws ServletException, IOException {
        request.addHeader("Authorization", "Bearer valid.jwt.token");
        when(jwtUtils.validateJwtToken("valid.jwt.token")).thenReturn(true);
        when(jwtUtils.getUserNameFromJwtToken("valid.jwt.token")).thenReturn("testuser");

        filter.doFilterInternal(request, response, filterChain);

        assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities().isEmpty());
    }
}
