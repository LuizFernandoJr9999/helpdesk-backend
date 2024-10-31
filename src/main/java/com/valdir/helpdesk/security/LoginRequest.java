package com.valdir.helpdesk.security;

public class LoginRequest {

    private String username;
    private String password;

    // Construtor padrão
    public LoginRequest() {
    }

    // Construtor com argumentos
    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getters e Setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
