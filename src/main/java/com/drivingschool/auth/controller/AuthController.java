package com.drivingschool.auth.controller;

import com.drivingschool.auth.entity.User;
import com.drivingschool.auth.payload.JwtResponse;
import com.drivingschool.auth.payload.LoginRequest;
import com.drivingschool.auth.payload.SignupRequest;
import com.drivingschool.auth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "User registration and authentication endpoints")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    @Operation(summary = "Register a new user")
    public ResponseEntity<Map<String, String>> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        User user = userService.register(signUpRequest);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "User registered successfully", "username", user.getUsername()));
    }

    @PostMapping("/signin")
    @Operation(summary = "Authenticate and receive JWT token")
    public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        JwtResponse response = userService.authenticate(loginRequest);
        return ResponseEntity.ok(response);
    }
}

