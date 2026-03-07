package com.drivingschool.auth.payload;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class LoginRequestTest {

    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    private LoginRequest create(String username, String password) {
        LoginRequest req = new LoginRequest();
        req.setUsername(username);
        req.setPassword(password);
        return req;
    }

    // --- Getters/Setters ---

    @Test
    @DisplayName("getters and setters should work correctly")
    void gettersAndSetters() {
        LoginRequest req = new LoginRequest();
        req.setUsername("user");
        req.setPassword("pass");

        assertEquals("user", req.getUsername());
        assertEquals("pass", req.getPassword());
    }

    // --- Validation ---

    @Test
    @DisplayName("valid request should have no violations")
    void validRequest_noViolations() {
        LoginRequest req = create("user1", "password123");

        Set<ConstraintViolation<LoginRequest>> violations = validator.validate(req);
        assertTrue(violations.isEmpty());
    }

    @Test
    @DisplayName("blank username should produce violation")
    void blankUsername_shouldViolate() {
        LoginRequest req = create("", "password123");

        Set<ConstraintViolation<LoginRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v ->
                v.getPropertyPath().toString().equals("username")));
    }

    @Test
    @DisplayName("null username should produce violation")
    void nullUsername_shouldViolate() {
        LoginRequest req = create(null, "password123");

        Set<ConstraintViolation<LoginRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("blank password should produce violation")
    void blankPassword_shouldViolate() {
        LoginRequest req = create("user1", "");

        Set<ConstraintViolation<LoginRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v ->
                v.getPropertyPath().toString().equals("password")));
    }

    @Test
    @DisplayName("null password should produce violation")
    void nullPassword_shouldViolate() {
        LoginRequest req = create("user1", null);

        Set<ConstraintViolation<LoginRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("both fields blank should produce two violations")
    void bothBlank_shouldProduceTwoViolations() {
        LoginRequest req = create("", "");

        Set<ConstraintViolation<LoginRequest>> violations = validator.validate(req);
        assertEquals(2, violations.size());
    }
}
