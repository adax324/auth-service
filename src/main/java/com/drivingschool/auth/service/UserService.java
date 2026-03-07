package com.drivingschool.auth.service;

import com.drivingschool.auth.entity.User;
import com.drivingschool.auth.payload.JwtResponse;
import com.drivingschool.auth.payload.LoginRequest;
import com.drivingschool.auth.payload.SignupRequest;
import com.drivingschool.auth.repository.UserRepository;
import com.drivingschool.auth.security.JwtUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
            throw new IllegalArgumentException("Username taken");
        }
        User u = new User(req.getUsername(), passwordEncoder.encode(req.getPassword()));
        return userRepository.save(u);
    }

    public JwtResponse authenticate(LoginRequest req) {
        User user = userRepository.findByUsername(req.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        String token = jwtUtils.generateJwtToken(user.getUsername());
        return new JwtResponse(token, user.getUsername());
    }
}

