package com.drivingschool.auth.exception;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
    }

    // --- handleValidationExceptions ---

    @Test
    @DisplayName("handleValidationExceptions - should return 400 with field errors")
    void handleValidation_shouldReturn400WithFieldErrors() {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "target");
        bindingResult.addError(new FieldError("target", "username", "Username is required"));
        bindingResult.addError(new FieldError("target", "password", "Password must be at least 6 characters"));

        MethodArgumentNotValidException ex =
                new MethodArgumentNotValidException(null, bindingResult);

        ResponseEntity<Map<String, Object>> response = handler.handleValidationExceptions(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(400, response.getBody().get("status"));
        assertNotNull(response.getBody().get("timestamp"));

        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) response.getBody().get("errors");
        assertEquals("Username is required", errors.get("username"));
        assertEquals("Password must be at least 6 characters", errors.get("password"));
    }

    @Test
    @DisplayName("handleValidationExceptions - should handle single field error")
    void handleValidation_singleFieldError() {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "target");
        bindingResult.addError(new FieldError("target", "email", "Email is invalid"));

        MethodArgumentNotValidException ex =
                new MethodArgumentNotValidException(null, bindingResult);

        ResponseEntity<Map<String, Object>> response = handler.handleValidationExceptions(ex);

        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) response.getBody().get("errors");
        assertEquals(1, errors.size());
        assertEquals("Email is invalid", errors.get("email"));
    }

    // --- handleIllegalArgumentException ---

    @Test
    @DisplayName("handleIllegalArgumentException - should return 400 with exception message")
    void handleIllegalArg_shouldReturn400WithMessage() {
        IllegalArgumentException ex = new IllegalArgumentException("Username taken");

        ResponseEntity<Map<String, Object>> response = handler.handleIllegalArgumentException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(400, response.getBody().get("status"));
        assertEquals("Username taken", response.getBody().get("message"));
        assertNotNull(response.getBody().get("timestamp"));
    }

    @Test
    @DisplayName("handleIllegalArgumentException - should handle empty message")
    void handleIllegalArg_emptyMessage() {
        IllegalArgumentException ex = new IllegalArgumentException("");

        ResponseEntity<Map<String, Object>> response = handler.handleIllegalArgumentException(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("", response.getBody().get("message"));
    }

    // --- handleUserAlreadyExistsException ---

    @Test
    @DisplayName("handleUserAlreadyExistsException - should return 409 with exception message")
    void handleUserAlreadyExists_shouldReturn409WithMessage() {
        UserAlreadyExistsException ex = new UserAlreadyExistsException("testuser");

        ResponseEntity<Map<String, Object>> response = handler.handleUserAlreadyExistsException(ex);

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(409, response.getBody().get("status"));
        assertTrue(response.getBody().get("message").toString().contains("testuser"));
        assertNotNull(response.getBody().get("timestamp"));
    }

    // --- handleBadCredentials ---

    @Test
    @DisplayName("handleBadCredentials - should return 401 with generic message")
    void handleBadCredentials_shouldReturn401() {
        BadCredentialsException ex = new BadCredentialsException("Invalid credentials");

        ResponseEntity<Map<String, Object>> response = handler.handleBadCredentials(ex);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(401, response.getBody().get("status"));
        assertEquals("Invalid credentials", response.getBody().get("message"));
        assertNotNull(response.getBody().get("timestamp"));
    }

    @Test
    @DisplayName("handleBadCredentials - should not leak original exception message")
    void handleBadCredentials_shouldNotLeakDetails() {
        BadCredentialsException ex = new BadCredentialsException("User 'admin' not found in database");

        ResponseEntity<Map<String, Object>> response = handler.handleBadCredentials(ex);

        assertEquals("Invalid credentials", response.getBody().get("message"));
    }

    // --- handleGlobalException ---

    @Test
    @DisplayName("handleGlobalException - should return 500 with generic message only")
    void handleGlobal_shouldReturn500WithGenericMessage() {
        Exception ex = new RuntimeException("Something broke internally");

        ResponseEntity<Map<String, Object>> response = handler.handleGlobalException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(500, response.getBody().get("status"));
        assertEquals("An unexpected error occurred", response.getBody().get("message"));
        assertNull(response.getBody().get("error"), "Should not leak internal error details");
        assertNotNull(response.getBody().get("timestamp"));
    }

    @Test
    @DisplayName("handleGlobalException - should handle null message exception")
    void handleGlobal_nullMessage() {
        Exception ex = new NullPointerException();

        ResponseEntity<Map<String, Object>> response = handler.handleGlobalException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("An unexpected error occurred", response.getBody().get("message"));
    }
}
