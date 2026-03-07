package com.drivingschool.auth.service;

import com.drivingschool.auth.entity.User;
import com.drivingschool.auth.exception.UserAlreadyExistsException;
import com.drivingschool.auth.payload.JwtResponse;
import com.drivingschool.auth.payload.LoginRequest;
import com.drivingschool.auth.payload.SignupRequest;
import com.drivingschool.auth.repository.UserRepository;
import com.drivingschool.auth.security.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

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
            logger.warn("Registration failed: username '{}' is already taken", req.getUsername());
            throw new UserAlreadyExistsException(req.getUsername());
        }
        User u = new User(req.getUsername(), passwordEncoder.encode(req.getPassword()));
        User saved = userRepository.save(u);
        logger.info("User registered successfully: username='{}'", saved.getUsername());
        return saved;
    }

    public JwtResponse authenticate(LoginRequest req) {
        User user = userRepository.findByUsername(req.getUsername())
                .orElseThrow(() -> {
                    logger.warn("Authentication failed for username='{}'", req.getUsername());
                    return new BadCredentialsException("Invalid credentials");
                });

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            logger.warn("Authentication failed for username='{}'", req.getUsername());
            throw new BadCredentialsException("Invalid credentials");
        }

        String token = jwtUtils.generateJwtToken(user.getUsername());
        logger.info("User authenticated successfully: username='{}'", user.getUsername());
        return new JwtResponse(token, user.getUsername());
    }
}

