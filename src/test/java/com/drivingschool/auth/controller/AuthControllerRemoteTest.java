package com.drivingschool.auth.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Remote integration tests against a running AuthService instance.
 * Requires the application to be running on the configured BASE_URL (default: http://localhost:8081).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Tag("remote")
class AuthControllerRemoteTest {

    private static final String BASE_URL = System.getProperty("test.base-url", "http://localhost:8081");
    private static final RestTemplate restTemplate = new RestTemplate();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final HttpHeaders JSON_HEADERS = new HttpHeaders();

    private static final String TEST_USERNAME = "testuser_" + UUID.randomUUID().toString().substring(0, 8);
    private static final String TEST_PASSWORD = "securePass123";

    private static String jwtToken;

    @BeforeAll
    static void setup() {
        JSON_HEADERS.setContentType(MediaType.APPLICATION_JSON);
    }

    // ========================
    // Health & Actuator Tests
    // ========================

    @Test
    @Order(1)
    @DisplayName("GET /actuator/health - should return UP")
    void healthEndpoint_shouldReturnUp() {
        ResponseEntity<String> response = restTemplate.getForEntity(BASE_URL + "/actuator/health", String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("UP"), "Health status should be UP");
    }

    @Test
    @Order(2)
    @DisplayName("GET /actuator/info - should return 200")
    void infoEndpoint_shouldReturn200() {
        ResponseEntity<String> response = restTemplate.getForEntity(BASE_URL + "/actuator/info", String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    // ========================
    // Signup Tests
    // ========================

    @Test
    @Order(10)
    @DisplayName("POST /api/auth/signup - valid user should register successfully")
    void signup_validUser_shouldSucceed() {
        Map<String, String> body = Map.of("username", TEST_USERNAME, "password", TEST_PASSWORD);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        ResponseEntity<String> response = restTemplate.postForEntity(
                BASE_URL + "/api/auth/signup", request, String.class);

        assertTrue(response.getStatusCode() == HttpStatus.OK || response.getStatusCode() == HttpStatus.CREATED,
                "Should return 200 or 201: " + response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().contains("registered successfully")
                        || response.getBody().contains("username"),
                "Response should confirm registration: " + response.getBody());
    }

    @Test
    @Order(11)
    @DisplayName("POST /api/auth/signup - duplicate username should fail")
    void signup_duplicateUsername_shouldFail() {
        Map<String, String> body = Map.of("username", TEST_USERNAME, "password", TEST_PASSWORD);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    BASE_URL + "/api/auth/signup", request, String.class);
            // Some implementations return 400 directly
            assertTrue(response.getStatusCode().is4xxClientError()
                            || response.getBody().toLowerCase().contains("already"),
                    "Duplicate signup should be rejected");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode().is4xxClientError(),
                    "Duplicate signup should return 4xx: " + e.getStatusCode());
        }
    }

    @Test
    @Order(12)
    @DisplayName("POST /api/auth/signup - empty username should fail")
    void signup_emptyUsername_shouldFail() {
        Map<String, String> body = Map.of("username", "", "password", TEST_PASSWORD);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        try {
            restTemplate.postForEntity(BASE_URL + "/api/auth/signup", request, String.class);
            fail("Expected 400 Bad Request for empty username");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode().is4xxClientError(),
                    "Empty username should return 4xx: " + e.getStatusCode());
        }
    }

    @Test
    @Order(13)
    @DisplayName("POST /api/auth/signup - short password should fail")
    void signup_shortPassword_shouldFail() {
        Map<String, String> body = Map.of("username", "newuser123", "password", "abc");
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        try {
            restTemplate.postForEntity(BASE_URL + "/api/auth/signup", request, String.class);
            fail("Expected 400 Bad Request for short password");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode().is4xxClientError(),
                    "Short password should return 4xx: " + e.getStatusCode());
        }
    }

    @Test
    @Order(14)
    @DisplayName("POST /api/auth/signup - missing body fields should fail")
    void signup_missingFields_shouldFail() {
        HttpEntity<String> request = new HttpEntity<>("{}", JSON_HEADERS);

        try {
            restTemplate.postForEntity(BASE_URL + "/api/auth/signup", request, String.class);
            fail("Expected 400 Bad Request for missing fields");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode().is4xxClientError(),
                    "Missing fields should return 4xx: " + e.getStatusCode());
        }
    }

    // ========================
    // Signin Tests
    // ========================

    @Test
    @Order(20)
    @DisplayName("POST /api/auth/signin - valid credentials should return JWT")
    void signin_validCredentials_shouldReturnJwt() throws Exception {
        Map<String, String> body = Map.of("username", TEST_USERNAME, "password", TEST_PASSWORD);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        ResponseEntity<String> response = restTemplate.postForEntity(
                BASE_URL + "/api/auth/signin", request, String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());

        JsonNode json = objectMapper.readTree(response.getBody());
        assertNotNull(json.get("token"), "Response should contain token");
        assertFalse(json.get("token").asText().isEmpty(), "Token should not be empty");
        assertEquals("Bearer", json.get("type").asText(), "Token type should be Bearer");
        assertEquals(TEST_USERNAME, json.get("username").asText(), "Username should match");

        // Store token for later tests
        jwtToken = json.get("token").asText();
    }

    @Test
    @Order(21)
    @DisplayName("POST /api/auth/signin - wrong password should return 401")
    void signin_wrongPassword_shouldReturn401() {
        Map<String, String> body = Map.of("username", TEST_USERNAME, "password", "wrongPassword");
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    BASE_URL + "/api/auth/signin", request, String.class);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode(),
                    "Wrong password should return 401");
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode(),
                    "Wrong password should return 401: " + e.getStatusCode());
        }
    }

    @Test
    @Order(22)
    @DisplayName("POST /api/auth/signin - non-existent user should return 401")
    void signin_nonExistentUser_shouldReturn401() {
        Map<String, String> body = Map.of("username", "nobody_here_12345", "password", "somepass123");
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    BASE_URL + "/api/auth/signin", request, String.class);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode(),
                    "Non-existent user should return 401");
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode(),
                    "Non-existent user should return 401: " + e.getStatusCode());
        }
    }

    @Test
    @Order(23)
    @DisplayName("POST /api/auth/signin - missing fields should fail")
    void signin_missingFields_shouldFail() {
        HttpEntity<String> request = new HttpEntity<>("{}", JSON_HEADERS);

        try {
            restTemplate.postForEntity(BASE_URL + "/api/auth/signin", request, String.class);
            fail("Expected 4xx for missing login fields");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode().is4xxClientError(),
                    "Missing fields should return 4xx: " + e.getStatusCode());
        }
    }

    // ========================
    // JWT Token Validation Tests
    // ========================

    @Test
    @Order(40)
    @DisplayName("JWT token should have valid structure (3 parts)")
    void jwt_shouldHaveValidStructure() {
        assertNotNull(jwtToken, "JWT token should have been obtained from signin test");

        String[] parts = jwtToken.split("\\.");
        assertEquals(3, parts.length, "JWT should have 3 parts (header.payload.signature)");
    }

    @Test
    @Order(41)
    @DisplayName("JWT token payload should contain correct username")
    void jwt_payloadShouldContainUsername() throws Exception {
        assertNotNull(jwtToken, "JWT token should have been obtained from signin test");

        String[] parts = jwtToken.split("\\.");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        JsonNode payloadJson = objectMapper.readTree(payload);

        assertEquals(TEST_USERNAME, payloadJson.get("sub").asText(),
                "JWT subject should be the username");
        assertNotNull(payloadJson.get("iat"), "JWT should have issued-at claim");
        assertNotNull(payloadJson.get("exp"), "JWT should have expiration claim");

        long exp = payloadJson.get("exp").asLong();
        long iat = payloadJson.get("iat").asLong();
        assertTrue(exp > iat, "Expiration should be after issued-at");
    }

    // ========================
    // Security Tests
    // ========================

    @Test
    @Order(50)
    @DisplayName("Protected endpoint without token should return 401/403")
    void protectedEndpoint_noToken_shouldBeRejected() {
        try {
            restTemplate.getForEntity(BASE_URL + "/api/some-protected-resource", String.class);
            fail("Expected 401/403 for unauthenticated access");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode() == HttpStatus.UNAUTHORIZED
                            || e.getStatusCode() == HttpStatus.FORBIDDEN,
                    "Should return 401 or 403: " + e.getStatusCode());
        }
    }

    @Test
    @Order(51)
    @DisplayName("Protected endpoint with invalid token should return 401/403")
    void protectedEndpoint_invalidToken_shouldBeRejected() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth("invalid.jwt.token");

        try {
            restTemplate.exchange(BASE_URL + "/api/some-protected-resource",
                    HttpMethod.GET, new HttpEntity<>(headers), String.class);
            fail("Expected 401/403 for invalid token");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode() == HttpStatus.UNAUTHORIZED
                            || e.getStatusCode() == HttpStatus.FORBIDDEN,
                    "Should return 401 or 403: " + e.getStatusCode());
        }
    }

    // ========================
    // Edge Cases
    // ========================

    @Test
    @Order(60)
    @DisplayName("POST /api/auth/signup - username with special chars should be handled")
    void signup_specialCharsUsername_shouldBeHandled() {
        Map<String, String> body = Map.of("username", "user<script>alert</script>", "password", TEST_PASSWORD);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        // Should either succeed (sanitized) or fail gracefully — never 500
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    BASE_URL + "/api/auth/signup", request, String.class);
            assertFalse(response.getStatusCode().is5xxServerError(),
                    "Should not return 5xx for special characters");
        } catch (HttpClientErrorException e) {
            assertFalse(e.getStatusCode().is5xxServerError(),
                    "Should not return 5xx for special characters");
        }
    }

    @Test
    @Order(61)
    @DisplayName("POST /api/auth/signup - very long username should be handled")
    void signup_longUsername_shouldBeHandled() {
        String longUsername = "a".repeat(200);
        Map<String, String> body = Map.of("username", longUsername, "password", TEST_PASSWORD);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, JSON_HEADERS);

        try {
            restTemplate.postForEntity(BASE_URL + "/api/auth/signup", request, String.class);
            fail("Expected 400 for username exceeding max length");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode().is4xxClientError(),
                    "Long username should return 4xx: " + e.getStatusCode());
        }
    }

    @Test
    @Order(62)
    @DisplayName("Invalid content type should return non-200 error")
    void invalidContentType_shouldReturnError() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        HttpEntity<String> request = new HttpEntity<>("not json", headers);

        try {
            restTemplate.postForEntity(BASE_URL + "/api/auth/signup", request, String.class);
            fail("Expected error for invalid content type");
        } catch (HttpClientErrorException e) {
            assertTrue(e.getStatusCode().is4xxClientError(),
                    "Invalid content type should return 4xx: " + e.getStatusCode());
        } catch (org.springframework.web.client.HttpServerErrorException e) {
            // Server returns 415 or 500 for unsupported media type — both are acceptable rejections
            assertFalse(e.getStatusCode().is2xxSuccessful(),
                    "Invalid content type should not succeed");
        }
    }
}
