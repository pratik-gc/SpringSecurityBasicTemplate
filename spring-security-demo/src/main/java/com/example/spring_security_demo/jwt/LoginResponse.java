package com.example.spring_security_demo.jwt;

import java.util.List;

public class LoginResponse {

    private String username;
    private List<String> roles;
    private String jwtToken;

    public LoginResponse() {
    }

    public LoginResponse(String username, List<String> roles, String jwtToken) {
        this.jwtToken = jwtToken;
        this.username = username;
        this.roles = roles;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
