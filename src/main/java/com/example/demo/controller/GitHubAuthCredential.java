/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.demo.controller;

/**
 *
 * @author aemtechnology
 */
public class GitHubAuthCredential {
       private final String accessToken;

    public GitHubAuthCredential(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getProvider() {
        return "github.com";
    }

    public String getSignInMethod() {
        return "github.com";
    }

    public String getAccessToken() {
        return accessToken;
    }

}
