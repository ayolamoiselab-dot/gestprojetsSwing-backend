package com.example.demo.config;

import java.util.HashMap;
import java.util.Map;

public class TemporaryUserStorage {
    private static final Map<String, UserData> tempUsers = new HashMap<>();

    public static void store(String uid, String fullName, String email, String password) {
        tempUsers.put(uid, new UserData(fullName, email, password));
    }

    public static UserData get(String uid) {
        return tempUsers.get(uid);
    }

    public static void remove(String uid) {
        tempUsers.remove(uid);
    }

    public static class UserData {
        private final String fullName;
        private final String email;
        private final String password;

        public UserData(String fullName, String email, String password) {
            this.fullName = fullName;
            this.email = email;
            this.password = password;
        }

        public String getFullName() {
            return fullName;
        }

        public String getEmail() {
            return email;
        }

        public String getPassword() {
            return password;
        }
    }
}