package com.drivingschool.auth.service;

import com.drivingschool.auth.entity.User;
import com.drivingschool.auth.payload.JwtResponse;
import com.drivingschool.auth.payload.LoginRequest;
import com.drivingschool.auth.payload.SignupRequest;
import com.drivingschool.auth.repository.UserRepository;
import com.drivingschool.auth.security.JwtUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtils jwtUtils;

    @InjectMocks
    private UserService userService;

    private SignupRequest createSignupRequest(String username, String password) {
        SignupRequest req = new SignupRequest();
        req.setUsername(username);
        req.setPassword(password);
        return req;
    }

    private LoginRequest createLoginRequest(String username, String password) {
        LoginRequest req = new LoginRequest();
        req.setUsername(username);
        req.setPassword(password);
        return req;
    }

    @Nested
    @DisplayName("register")
    class Register {

        @Test
        @DisplayName("should save user with encoded password and return saved entity")
        void shouldSaveUserWithEncodedPassword() {
            SignupRequest req = createSignupRequest("newuser", "plainPassword");
            when(userRepository.existsByUsername("newuser")).thenReturn(false);
            when(passwordEncoder.encode("plainPassword")).thenReturn("$2a$10$encodedHash");
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User u = invocation.getArgument(0);
                u.setId(1L);
                return u;
            });

            User result = userService.register(req);

            assertNotNull(result);
            assertEquals("newuser", result.getUsername());
            assertEquals("$2a$10$encodedHash", result.getPassword());
            assertEquals(1L, result.getId());
        }

        @Test
        @DisplayName("should encode password before saving")
        void shouldEncodePasswordBeforeSaving() {
            SignupRequest req = createSignupRequest("user1", "rawPass123");
            when(userRepository.existsByUsername("user1")).thenReturn(false);
            when(passwordEncoder.encode("rawPass123")).thenReturn("encodedPass");
            when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

            userService.register(req);

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            assertEquals("encodedPass", captor.getValue().getPassword());
        }

        @Test
        @DisplayName("should check username existence before saving")
        void shouldCheckUsernameExistence() {
            SignupRequest req = createSignupRequest("testuser", "password123");
            when(userRepository.existsByUsername("testuser")).thenReturn(false);
            when(passwordEncoder.encode(any())).thenReturn("encoded");
            when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

            userService.register(req);

            var inOrder = inOrder(userRepository);
            inOrder.verify(userRepository).existsByUsername("testuser");
            inOrder.verify(userRepository).save(any(User.class));
        }

        @Test
        @DisplayName("should throw IllegalArgumentException when username already exists")
        void duplicateUsername_shouldThrow() {
            SignupRequest req = createSignupRequest("existing", "password123");
            when(userRepository.existsByUsername("existing")).thenReturn(true);

            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> userService.register(req));

            assertEquals("Username taken", ex.getMessage());
            verify(userRepository, never()).save(any());
            verify(passwordEncoder, never()).encode(any());
        }

        @Test
        @DisplayName("should call save exactly once")
        void shouldCallSaveOnce() {
            SignupRequest req = createSignupRequest("user", "password");
            when(userRepository.existsByUsername("user")).thenReturn(false);
            when(passwordEncoder.encode(any())).thenReturn("enc");
            when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

            userService.register(req);

            verify(userRepository, times(1)).save(any(User.class));
        }
    }

    @Nested
    @DisplayName("authenticate")
    class Authenticate {

        @Test
        @DisplayName("should return JwtResponse for valid credentials")
        void validCredentials_shouldReturnJwtResponse() {
            User user = new User("testuser", "$2a$10$encoded");
            when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
            when(passwordEncoder.matches("password123", "$2a$10$encoded")).thenReturn(true);
            when(jwtUtils.generateJwtToken("testuser")).thenReturn("jwt.token.here");

            JwtResponse response = userService.authenticate(createLoginRequest("testuser", "password123"));

            assertEquals("jwt.token.here", response.getToken());
            assertEquals("testuser", response.getUsername());
            assertEquals("Bearer", response.getType());
        }

        @Test
        @DisplayName("should throw BadCredentialsException when user not found")
        void userNotFound_shouldThrow() {
            when(userRepository.findByUsername("unknown")).thenReturn(Optional.empty());

            assertThrows(BadCredentialsException.class,
                    () -> userService.authenticate(createLoginRequest("unknown", "pass")));
        }

        @Test
        @DisplayName("should throw BadCredentialsException when password is wrong")
        void wrongPassword_shouldThrow() {
            User user = new User("testuser", "$2a$10$encoded");
            when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
            when(passwordEncoder.matches("wrongpass", "$2a$10$encoded")).thenReturn(false);

            assertThrows(BadCredentialsException.class,
                    () -> userService.authenticate(createLoginRequest("testuser", "wrongpass")));
        }

        @Test
        @DisplayName("should not generate JWT when password is wrong")
        void wrongPassword_shouldNotGenerateJwt() {
            User user = new User("testuser", "$2a$10$encoded");
            when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
            when(passwordEncoder.matches(any(), any())).thenReturn(false);

            assertThrows(BadCredentialsException.class,
                    () -> userService.authenticate(createLoginRequest("testuser", "wrongpass")));

            verify(jwtUtils, never()).generateJwtToken(any());
        }

        @Test
        @DisplayName("should call passwordEncoder.matches with correct arguments")
        void shouldCallPasswordEncoderCorrectly() {
            User user = new User("testuser", "$2a$10$hashed");
            when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));
            when(passwordEncoder.matches(any(), any())).thenReturn(true);
            when(jwtUtils.generateJwtToken(any())).thenReturn("token");

            userService.authenticate(createLoginRequest("testuser", "myPassword"));

            verify(passwordEncoder).matches("myPassword", "$2a$10$hashed");
        }
    }
}
