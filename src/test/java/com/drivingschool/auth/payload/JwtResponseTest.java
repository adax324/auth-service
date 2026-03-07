package com.drivingschool.auth.payload;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class JwtResponseTest {

    @Test
    @DisplayName("constructor should set token and username")
    void constructor_shouldSetTokenAndUsername() {
        JwtResponse response = new JwtResponse("myToken123", "john");

        assertEquals("myToken123", response.getToken());
        assertEquals("john", response.getUsername());
    }

    @Test
    @DisplayName("type should default to Bearer")
    void type_shouldDefaultToBearer() {
        JwtResponse response = new JwtResponse("token", "user");

        assertEquals("Bearer", response.getType());
    }

    @Test
    @DisplayName("setToken should update token value")
    void setToken_shouldUpdateToken() {
        JwtResponse response = new JwtResponse("old", "user");
        response.setToken("newToken");

        assertEquals("newToken", response.getToken());
    }

    @Test
    @DisplayName("setType should update type value")
    void setType_shouldUpdateType() {
        JwtResponse response = new JwtResponse("token", "user");
        response.setType("Custom");

        assertEquals("Custom", response.getType());
    }

    @Test
    @DisplayName("setUsername should update username value")
    void setUsername_shouldUpdateUsername() {
        JwtResponse response = new JwtResponse("token", "oldUser");
        response.setUsername("newUser");

        assertEquals("newUser", response.getUsername());
    }

    @Test
    @DisplayName("constructor should handle null values")
    void constructor_shouldHandleNulls() {
        JwtResponse response = new JwtResponse(null, null);

        assertNull(response.getToken());
        assertNull(response.getUsername());
        assertEquals("Bearer", response.getType());
    }
}
