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

class SignupRequestTest {

    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    private SignupRequest create(String username, String password) {
        SignupRequest req = new SignupRequest();
        req.setUsername(username);
        req.setPassword(password);
        return req;
    }

    // --- Getters/Setters ---

    @Test
    @DisplayName("getters and setters should work correctly")
    void gettersAndSetters() {
        SignupRequest req = new SignupRequest();
        req.setUsername("testUser");
        req.setPassword("testPass");

        assertEquals("testUser", req.getUsername());
        assertEquals("testPass", req.getPassword());
    }

    // --- Validation ---

    @Test
    @DisplayName("valid request should have no violations")
    void validRequest_noViolations() {
        SignupRequest req = create("validUser", "validPass123");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertTrue(violations.isEmpty());
    }

    @Test
    @DisplayName("blank username should produce violation")
    void blankUsername_shouldViolate() {
        SignupRequest req = create("", "validPass123");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("username")));
    }

    @Test
    @DisplayName("null username should produce violation")
    void nullUsername_shouldViolate() {
        SignupRequest req = create(null, "validPass123");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("username shorter than 3 chars should produce violation")
    void shortUsername_shouldViolate() {
        SignupRequest req = create("ab", "validPass123");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v ->
                v.getMessage().contains("between 3 and 50")));
    }

    @Test
    @DisplayName("username with exactly 3 chars should pass")
    void username3Chars_shouldPass() {
        SignupRequest req = create("abc", "validPass123");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertTrue(violations.isEmpty());
    }

    @Test
    @DisplayName("username with exactly 50 chars should pass")
    void username50Chars_shouldPass() {
        SignupRequest req = create("a".repeat(50), "validPass123");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertTrue(violations.isEmpty());
    }

    @Test
    @DisplayName("username longer than 50 chars should produce violation")
    void longUsername_shouldViolate() {
        SignupRequest req = create("a".repeat(51), "validPass123");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("blank password should produce violation")
    void blankPassword_shouldViolate() {
        SignupRequest req = create("validUser", "");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("password")));
    }

    @Test
    @DisplayName("null password should produce violation")
    void nullPassword_shouldViolate() {
        SignupRequest req = create("validUser", null);

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("password shorter than 6 chars should produce violation")
    void shortPassword_shouldViolate() {
        SignupRequest req = create("validUser", "12345");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v ->
                v.getMessage().contains("at least 6")));
    }

    @Test
    @DisplayName("password with exactly 6 chars should pass")
    void password6Chars_shouldPass() {
        SignupRequest req = create("validUser", "123456");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertTrue(violations.isEmpty());
    }

    @Test
    @DisplayName("password with 100 chars should pass")
    void password100Chars_shouldPass() {
        SignupRequest req = create("validUser", "a".repeat(100));

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertTrue(violations.isEmpty());
    }

    @Test
    @DisplayName("password longer than 100 chars should produce violation")
    void passwordOver100Chars_shouldViolate() {
        SignupRequest req = create("validUser", "a".repeat(101));

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(req);
        assertFalse(violations.isEmpty());
    }
}
