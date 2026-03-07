package com.drivingschool.auth.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {

    private JwtUtils jwtUtils;

    private static final String SECRET = "testSecretKeyForUnitTestingPurposesOnlyMustBeLongEnoughForHS512Algorithm!";
    private static final int EXPIRATION_MS = 86400000;
    private static final SecretKey KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils(SECRET, EXPIRATION_MS);
    }

    @Nested
    @DisplayName("generateJwtToken")
    class GenerateToken {

        @Test
        @DisplayName("should return a non-null, non-empty token")
        void shouldReturnNonEmptyToken() {
            String token = jwtUtils.generateJwtToken("testuser");

            assertNotNull(token);
            assertFalse(token.isEmpty());
        }

        @Test
        @DisplayName("should produce a valid JWT with 3 parts")
        void shouldHaveThreeParts() {
            String token = jwtUtils.generateJwtToken("testuser");

            String[] parts = token.split("\\.");
            assertEquals(3, parts.length, "JWT should have header.payload.signature");
        }

        @Test
        @DisplayName("should set the subject to the provided username")
        void shouldSetCorrectSubject() {
            String username = "john_doe";
            String token = jwtUtils.generateJwtToken(username);

            String extracted = Jwts.parser().verifyWith(KEY).build()
                    .parseSignedClaims(token).getPayload().getSubject();
            assertEquals(username, extracted);
        }

        @Test
        @DisplayName("should set issued-at to approximately now")
        void shouldSetIssuedAt() {
            long before = System.currentTimeMillis() / 1000 * 1000;
            String token = jwtUtils.generateJwtToken("testuser");
            long after = System.currentTimeMillis() + 1000;

            Date issuedAt = Jwts.parser().verifyWith(KEY).build()
                    .parseSignedClaims(token).getPayload().getIssuedAt();

            assertTrue(issuedAt.getTime() >= before && issuedAt.getTime() <= after,
                    "issuedAt should be approximately now");
        }

        @Test
        @DisplayName("should set expiration to issuedAt + expirationMs")
        void shouldSetCorrectExpiration() {
            String token = jwtUtils.generateJwtToken("testuser");

            var claims = Jwts.parser().verifyWith(KEY).build()
                    .parseSignedClaims(token).getPayload();
            long diff = claims.getExpiration().getTime() - claims.getIssuedAt().getTime();
            assertEquals(EXPIRATION_MS, diff);
        }

        @Test
        @DisplayName("should generate different tokens for different usernames")
        void shouldGenerateDifferentTokensForDifferentUsers() {
            String token1 = jwtUtils.generateJwtToken("user1");
            String token2 = jwtUtils.generateJwtToken("user2");

            assertNotEquals(token1, token2);
        }

        @Test
        @DisplayName("should generate different tokens on successive calls (different iat)")
        void shouldGenerateDifferentTokensOnSuccessiveCalls() throws InterruptedException {
            String token1 = jwtUtils.generateJwtToken("sameuser");
            Thread.sleep(1100);
            String token2 = jwtUtils.generateJwtToken("sameuser");

            assertNotEquals(token1, token2);
        }
    }

    @Nested
    @DisplayName("getUserNameFromJwtToken")
    class GetUsername {

        @Test
        @DisplayName("should extract the correct username from a valid token")
        void shouldExtractUsername() {
            String username = "jane_doe";
            String token = jwtUtils.generateJwtToken(username);

            assertEquals(username, jwtUtils.getUserNameFromJwtToken(token));
        }

        @Test
        @DisplayName("should work with special characters in username")
        void shouldHandleSpecialCharacters() {
            String username = "user@domain.com";
            String token = jwtUtils.generateJwtToken(username);

            assertEquals(username, jwtUtils.getUserNameFromJwtToken(token));
        }

        @Test
        @DisplayName("should throw on malformed token")
        void shouldThrowOnMalformedToken() {
            assertThrows(Exception.class, () ->
                    jwtUtils.getUserNameFromJwtToken("not.a.valid.jwt"));
        }
    }

    @Nested
    @DisplayName("validateJwtToken")
    class ValidateToken {

        @Test
        @DisplayName("should return true for a valid token")
        void shouldReturnTrueForValidToken() {
            String token = jwtUtils.generateJwtToken("testuser");

            assertTrue(jwtUtils.validateJwtToken(token));
        }

        @Test
        @DisplayName("should return false for an expired token")
        void shouldReturnFalseForExpiredToken() {
            String expiredToken = Jwts.builder()
                    .subject("testuser")
                    .issuedAt(new Date(System.currentTimeMillis() - 10000))
                    .expiration(new Date(System.currentTimeMillis() - 5000))
                    .signWith(KEY)
                    .compact();

            assertFalse(jwtUtils.validateJwtToken(expiredToken));
        }

        @Test
        @DisplayName("should return false for a malformed token")
        void shouldReturnFalseForMalformedToken() {
            assertFalse(jwtUtils.validateJwtToken("this.is.garbage"));
        }

        @Test
        @DisplayName("should return false for a token with wrong signature")
        void shouldReturnFalseForWrongSignature() {
            SecretKey wrongKey = Keys.hmacShaKeyFor(
                    "differentSecretKeyThatDoesNotMatchTheOriginalOneUsedForSigning!!".getBytes(StandardCharsets.UTF_8));
            String token = Jwts.builder()
                    .subject("testuser")
                    .issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + 60000))
                    .signWith(wrongKey)
                    .compact();

            assertFalse(jwtUtils.validateJwtToken(token));
        }

        @Test
        @DisplayName("should return false for an empty string")
        void shouldReturnFalseForEmptyString() {
            assertFalse(jwtUtils.validateJwtToken(""));
        }

        @Test
        @DisplayName("should return false for null")
        void shouldReturnFalseForNull() {
            assertFalse(jwtUtils.validateJwtToken(null));
        }

        @Test
        @DisplayName("should return false for a token with only header and payload (no signature)")
        void shouldReturnFalseForUnsignedToken() {
            // Create a token string without a valid signature
            String unsignedToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0dXNlciJ9.";

            assertFalse(jwtUtils.validateJwtToken(unsignedToken));
        }
    }
}
