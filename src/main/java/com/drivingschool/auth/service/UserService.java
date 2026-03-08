package com.drivingschool.auth.service;

import com.drivingschool.auth.entity.User;
import com.drivingschool.auth.exception.UserAlreadyExistsException;
import com.drivingschool.auth.payload.JwtResponse;
import com.drivingschool.auth.payload.LoginRequest;
import com.drivingschool.auth.payload.SignupRequest;
import com.drivingschool.auth.repository.UserRepository;
import com.drivingschool.auth.security.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
    }

    @Transactional
    public User register(SignupRequest req) {
        if (userRepository.existsByUsername(req.getUsername())) {
            log.warn("Registration failed: username '{}' is already taken", req.getUsername());
            throw new UserAlreadyExistsException(req.getUsername());
        }
        try {
            User u = new User(req.getUsername(), passwordEncoder.encode(req.getPassword()));
            User saved = userRepository.save(u);
            log.info("User registered successfully: username='{}'", saved.getUsername());
            return saved;
        } catch (DataIntegrityViolationException e) {
            log.warn("Registration failed due to concurrent signup: username='{}'", req.getUsername());
            throw new UserAlreadyExistsException(req.getUsername());
        }
    }

    public JwtResponse authenticate(LoginRequest req) {
        User user = userRepository.findByUsername(req.getUsername())
                .orElseThrow(() -> authenticationFailure(req.getUsername()));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw authenticationFailure(req.getUsername());
        }

        String token = jwtUtils.generateJwtToken(user.getUsername());
        log.info("User authenticated successfully: username='{}'", user.getUsername());
        return new JwtResponse(token, user.getUsername());
    }

    private BadCredentialsException authenticationFailure(String username) {
        log.warn("Authentication failed for username='{}'", username);
        return new BadCredentialsException("Invalid credentials");
    }
}

