package com.drivingschool.auth.controller;

import com.drivingschool.auth.entity.User;
import com.drivingschool.auth.payload.JwtResponse;
import com.drivingschool.auth.payload.LoginRequest;
import com.drivingschool.auth.payload.SignupRequest;
import com.drivingschool.auth.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import com.drivingschool.auth.exception.UserAlreadyExistsException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private AuthController authController;

    private SignupRequest validSignup;
    private LoginRequest validLogin;

    @BeforeEach
    void setUp() {
        validSignup = new SignupRequest();
        validSignup.setUsername("testuser");
        validSignup.setPassword("password123");

        validLogin = new LoginRequest();
        validLogin.setUsername("testuser");
        validLogin.setPassword("password123");
    }

    @Nested
    @DisplayName("registerUser (POST /api/auth/signup)")
    class RegisterUser {

        @Test
        @DisplayName("should return 201 with success message for valid request")
        void validSignup_shouldReturn201() {
            User savedUser = new User("testuser", "encodedPass");
            savedUser.setId(1L);
            when(userService.register(any(SignupRequest.class))).thenReturn(savedUser);

            ResponseEntity<Map<String, String>> response = authController.registerUser(validSignup);

            assertEquals(HttpStatus.CREATED, response.getStatusCode());
            assertEquals("User registered successfully", response.getBody().get("message"));
            assertEquals("testuser", response.getBody().get("username"));
        }

        @Test
        @DisplayName("should call userService.register with the request")
        void shouldCallUserService() {
            User savedUser = new User("testuser", "encodedPass");
            when(userService.register(any(SignupRequest.class))).thenReturn(savedUser);

            authController.registerUser(validSignup);

            verify(userService, times(1)).register(any(SignupRequest.class));
        }

        @Test
        @DisplayName("should propagate UserAlreadyExistsException from service")
        void duplicateUsername_shouldPropagate() {
            when(userService.register(any(SignupRequest.class)))
                    .thenThrow(new UserAlreadyExistsException("testuser"));

            assertThrows(UserAlreadyExistsException.class, () -> authController.registerUser(validSignup));
        }
    }

    @Nested
    @DisplayName("authenticateUser (POST /api/auth/signin)")
    class AuthenticateUser {

        @Test
        @DisplayName("should return 200 with JWT for valid credentials")
        void validCredentials_shouldReturnJwt() {
            JwtResponse jwtResponse = new JwtResponse("jwt.token.here", "testuser");
            when(userService.authenticate(any(LoginRequest.class))).thenReturn(jwtResponse);

            ResponseEntity<JwtResponse> response = authController.authenticateUser(validLogin);

            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertEquals("jwt.token.here", response.getBody().getToken());
            assertEquals("testuser", response.getBody().getUsername());
            assertEquals("Bearer", response.getBody().getType());
        }

        @Test
        @DisplayName("should propagate BadCredentialsException for wrong password")
        void wrongPassword_shouldPropagate() {
            when(userService.authenticate(any(LoginRequest.class)))
                    .thenThrow(new BadCredentialsException("Invalid credentials"));

            assertThrows(BadCredentialsException.class, () -> authController.authenticateUser(validLogin));
        }

        @Test
        @DisplayName("should call userService.authenticate with the request")
        void shouldCallUserServiceAuthenticate() {
            JwtResponse jwtResponse = new JwtResponse("token", "testuser");
            when(userService.authenticate(any(LoginRequest.class))).thenReturn(jwtResponse);

            authController.authenticateUser(validLogin);

            verify(userService, times(1)).authenticate(any(LoginRequest.class));
        }
    }
}
