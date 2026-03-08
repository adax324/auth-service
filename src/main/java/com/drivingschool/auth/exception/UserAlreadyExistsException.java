package com.drivingschool.auth.exception;

public class UserAlreadyExistsException extends RuntimeException {

    private final String attemptedUsername;

    public UserAlreadyExistsException(String username) {
        super("Username already taken");
        this.attemptedUsername = username;
    }

    public String getAttemptedUsername() {
        return attemptedUsername;
    }
}
