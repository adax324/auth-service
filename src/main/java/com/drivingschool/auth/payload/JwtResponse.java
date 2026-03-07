package com.drivingschool.auth.payload;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String username;

    public JwtResponse(String token, String username) {
        this.token = token;
        this.username = username;
    }

}

