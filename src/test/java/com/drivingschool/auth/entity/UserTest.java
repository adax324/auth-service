package com.drivingschool.auth.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    @Test
    @DisplayName("no-arg constructor should create user with null fields")
    void noArgConstructor() {
        User user = new User();

        assertNull(user.getId());
        assertNull(user.getUsername());
        assertNull(user.getPassword());
    }

    @Test
    @DisplayName("parameterized constructor should set username and password")
    void parameterizedConstructor() {
        User user = new User("john", "secret123");

        assertEquals("john", user.getUsername());
        assertEquals("secret123", user.getPassword());
        assertNull(user.getId());
    }

    @Test
    @DisplayName("setId and getId should work correctly")
    void setAndGetId() {
        User user = new User();
        user.setId(42L);

        assertEquals(42L, user.getId());
    }

    @Test
    @DisplayName("setUsername and getUsername should work correctly")
    void setAndGetUsername() {
        User user = new User();
        user.setUsername("testUser");

        assertEquals("testUser", user.getUsername());
    }

    @Test
    @DisplayName("setPassword and getPassword should work correctly")
    void setAndGetPassword() {
        User user = new User();
        user.setPassword("newPassword");

        assertEquals("newPassword", user.getPassword());
    }

    @Test
    @DisplayName("should allow updating all fields after construction")
    void updateFields() {
        User user = new User("original", "origPass");
        user.setId(1L);
        user.setUsername("updated");
        user.setPassword("updatedPass");

        assertEquals(1L, user.getId());
        assertEquals("updated", user.getUsername());
        assertEquals("updatedPass", user.getPassword());
    }

    @Test
    @DisplayName("equals should be based on id (JPA best practice)")
    void equals_sameId() {
        User user1 = new User("alice", "pass");
        user1.setId(1L);
        User user2 = new User("bob", "other");
        user2.setId(1L);

        assertEquals(user1, user2, "Same ID should mean equal regardless of other fields");
    }

    @Test
    @DisplayName("users with null IDs should not be equal")
    void equals_nullIds() {
        User user1 = new User("alice", "pass");
        User user2 = new User("alice", "pass");

        assertNotEquals(user1, user2, "Unsaved entities (null ID) should not be equal");
    }

    @Test
    @DisplayName("different IDs should not be equal")
    void notEquals() {
        User user1 = new User("alice", "pass");
        user1.setId(1L);
        User user2 = new User("alice", "pass");
        user2.setId(2L);

        assertNotEquals(user1, user2);
    }

    @Test
    @DisplayName("toString should contain id and username but not password")
    void toString_shouldNotContainPassword() {
        User user = new User("alice", "secretpass");
        user.setId(1L);
        String str = user.toString();

        assertTrue(str.contains("alice"));
        assertTrue(str.contains("1"));
        assertFalse(str.contains("secretpass"), "toString should not expose password");
    }
}
