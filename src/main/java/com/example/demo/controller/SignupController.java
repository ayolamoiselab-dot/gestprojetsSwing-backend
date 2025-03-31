package com.example.demo.controller;

import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.auth.*;
import com.google.firebase.cloud.FirestoreClient;
import com.example.demo.config.TemporaryUserStorage;
import org.json.JSONObject;
import org.json.JSONArray;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api")
public class SignupController {

    private static final String FIREBASE_API_KEY = System.getenv("FIREBASE_API_KEY");
    private static final Map<String, Map<String, String>> tempSessions = new ConcurrentHashMap<>();

    @Autowired
    private HttpServletRequest request;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody String requestBody) {
        try {
            JSONObject json = new JSONObject(requestBody);
            String fullName = json.getString("fullName");
            String email = json.getString("email");
            String password = json.getString("password");

            UserRecord.CreateRequest createRequest = new UserRecord.CreateRequest()
                    .setEmail(email)
                    .setPassword(password)
                    .setDisplayName(fullName)
                    .setEmailVerified(false);

            UserRecord userRecord = FirebaseAuth.getInstance().createUser(createRequest);
            String uid = userRecord.getUid();

            String verificationLink = FirebaseAuth.getInstance().generateEmailVerificationLink(email) + "&uid=" + uid;
            TemporaryUserStorage.store(uid, fullName, email, password);

            sendVerificationEmail(email, verificationLink);

            return ResponseEntity.ok(new JSONObject()
                    .put("message", "User created, please verify your email.")
                    .put("uid", uid).toString());

        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(400).body("{\"error\":\"Error creating user: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\":\"Server error: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam("uid") String uid, @RequestParam("oobCode") String oobCode) {
        try {
            if (!verifyEmailWithOobCode(oobCode)) {
                return ResponseEntity.status(400).body("{\"error\":\"Invalid or expired verification link.\"}");
            }

            FirebaseAuth.getInstance().updateUser(new UserRecord.UpdateRequest(uid).setEmailVerified(true));
            UserRecord userRecord = FirebaseAuth.getInstance().getUser(uid);

            if (userRecord.isEmailVerified()) {
                TemporaryUserStorage.UserData userData = TemporaryUserStorage.get(uid);
                if (userData == null) {
                    return ResponseEntity.status(400).body("{\"error\":\"User data not found.\"}");
                }

                Firestore db = FirestoreClient.getFirestore();
                Map<String, Object> userMap = new HashMap<>();
                userMap.put("fullName", userData.getFullName());
                userMap.put("email", userData.getEmail());
                userMap.put("createdAt", System.currentTimeMillis());

                db.collection("users").document(uid).set(userMap);
                TemporaryUserStorage.remove(uid);

                return ResponseEntity.ok("{\"message\":\"Email verified, user created in Firestore.\"}");
            }
            return ResponseEntity.status(400).body("{\"error\":\"Email not yet verified.\"}");
        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(400).body("{\"error\":\"Error verifying user: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\":\"Server error: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/check-verification-status")
    public ResponseEntity<String> checkVerificationStatus(@RequestParam("uid") String uid) {
        try {
            UserRecord userRecord = FirebaseAuth.getInstance().getUser(uid);
            return ResponseEntity.ok(new JSONObject()
                    .put("status", userRecord.isEmailVerified() ? "verified" : "pending")
                    .toString());
        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(400).body("{\"error\":\"User not found: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/user/{uid}")
    public ResponseEntity<String> getUser(@PathVariable("uid") String uid) {
        try {
            DocumentSnapshot document = FirestoreClient.getFirestore()
                    .collection("users").document(uid).get().get();

            if (document.exists()) {
                Map<String, Object> userData = document.getData();
                return ResponseEntity.ok(new JSONObject()
                        .put("uid", uid)
                        .put("fullName", userData.get("fullName"))
                        .put("email", userData.get("email"))
                        .put("createdAt", userData.get("createdAt"))
                        .toString());
            }
            return ResponseEntity.status(404).body("{\"error\":\"User not found.\"}");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\":\"Server error: " + e.getMessage() + "\"}");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody String requestBody) {
        try {
            JSONObject json = new JSONObject(requestBody);
            String email = json.getString("email");
            String password = json.getString("password");

            HttpClient client = HttpClient.newHttpClient();
            String signInUrl = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" + FIREBASE_API_KEY;

            HttpResponse<String> response = client.send(
                    HttpRequest.newBuilder()
                            .uri(URI.create(signInUrl))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(new JSONObject()
                                    .put("email", email)
                                    .put("password", password)
                                    .put("returnSecureToken", true).toString()))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                return ResponseEntity.status(401).body("{\"error\":\"Invalid email or password.\"}");
            }

            String uid = new JSONObject(response.body()).getString("localId");
            return ResponseEntity.ok(new JSONObject()
                    .put("message", "Login successful.")
                    .put("uid", uid).toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\":\"Server error: " + e.getMessage() + "\"}");
        }
    }

    @PostMapping("/social-auth")
    public ResponseEntity<String> socialAuth(@RequestBody String requestBody) {
        try {
            JSONObject json = new JSONObject(requestBody);
            String provider = json.getString("provider");
            String idToken = json.getString("idToken");

            FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(idToken);
            String uid = decodedToken.getUid();

            saveUserToFirestore(uid, decodedToken.getEmail(), provider);

            return ResponseEntity.ok(new JSONObject()
                    .put("uid", uid)
                    .put("email", decodedToken.getEmail())
                    .put("fullName", decodedToken.getName())
                    .toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\":\"Authentication error: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/auth/callback")
    public void handleCallback(
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            HttpServletResponse response) throws IOException {

        try {
            JSONObject stateJson = new JSONObject(new String(Base64.getDecoder().decode(state)));
            String provider = stateJson.getString("provider");
            String accessToken = exchangeCodeForToken(provider, code);
            String email = getEmailFromProvider(provider, accessToken);
            String uid = email.replaceAll("[^a-zA-Z0-9]", "_");

            UserRecord userRecord = createOrUpdateUser(provider, email, accessToken);
            String sessionId = UUID.randomUUID().toString();

            Map<String, String> userInfo = new HashMap<>();
            userInfo.put("uid", userRecord.getUid());
            userInfo.put("email", email);
            userInfo.put("fullName", userRecord.getDisplayName());
            tempSessions.put(sessionId, userInfo);

            response.sendRedirect("gestionprojetsswing://auth-success?session=" + sessionId);
        } catch (Exception e) {
            response.sendRedirect("gestionprojetsswing://auth-error?message="
                    + URLEncoder.encode(e.getMessage(), "UTF-8"));
        }
    }

    @GetMapping("/auth/complete")
    public ResponseEntity<String> authComplete(
            @RequestParam(value = "token", required = false) String token,
            @RequestParam(value = "uid", required = false) String uid,
            @RequestParam(value = "error", required = false) String error) {

        if (error != null) {
            return ResponseEntity.status(400).body("{\"error\":\"" + error + "\"}");
        }
        return ResponseEntity.ok(new JSONObject()
                .put("status", "success")
                .put("token", token)
                .put("uid", uid)
                .toString());
    }

    @GetMapping("/auth/{provider}")
    public void authRedirect(@PathVariable String provider, HttpServletResponse response) throws IOException {
        try {
            String state = generateStateToken();
            response.sendRedirect(buildAuthUrl(provider, state));
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Error generating auth URL: " + e.getMessage());
        }
    }

    @GetMapping("/check-auth-status")
    public ResponseEntity<String> checkAuthStatus(HttpServletRequest request) {
        try {
            String idToken = extractToken(request);
            if (idToken == null) {
                return ResponseEntity.ok("{\"isAuthenticated\":false}");
            }

            FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(idToken);
            String uid = decodedToken.getUid();
            DocumentSnapshot userDoc = FirestoreClient.getFirestore()
                    .collection("users").document(uid).get().get();

            JSONObject response = new JSONObject()
                    .put("isAuthenticated", true)
                    .put("uid", uid);

            // Vérifier si le document existe et récupérer "fullName" avec une valeur par défaut
            String fullName = userDoc.exists() ? userDoc.getString("fullName") : "User";
            if (fullName == null) {
                fullName = "User"; // Valeur par défaut si fullName est null
            }

            response.put("fullName", fullName);

            return ResponseEntity.ok(response.toString());
        } catch (Exception e) {
            return ResponseEntity.ok("{\"isAuthenticated\":false}");
        }
    }

    public static Map<String, String> getSessionInfo(String sessionId) {
        return tempSessions.remove(sessionId);
    }

    private boolean verifyEmailWithOobCode(String oobCode) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("https://identitytoolkit.googleapis.com/v1/accounts:update?key=" + FIREBASE_API_KEY))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(new JSONObject().put("oobCode", oobCode).toString()))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        return response.statusCode() == 200;
    }

    private void sendVerificationEmail(String toEmail, String verificationLink) throws MessagingException {
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");

        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(
                        System.getenv("GMAIL_USER"),
                        System.getenv("GMAIL_PASSWORD"));
            }
        });

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(System.getenv("GMAIL_USER")));
        message.addRecipient(Message.RecipientType.TO, new InternetAddress(toEmail));
        message.setSubject("Verify Your Email");
        message.setText("Please click the following link to verify your email: " + verificationLink);

        Transport.send(message);
    }

    private String exchangeCodeForToken(String provider, String code) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String tokenUrl = provider.equals("github")
                ? "https://github.com/login/oauth/access_token"
                : "https://oauth2.googleapis.com/token";

        String requestBody = provider.equals("github")
                ? String.format(
                        "client_id=%s&client_secret=%s&code=%s&redirect_uri=%s",
                        System.getenv("GITHUB_CLIENT_ID"),
                        System.getenv("GITHUB_CLIENT_SECRET"),
                        code,
                        URLEncoder.encode("https://gestprojetsswing-backend.onrender.com/api/auth/callback", "UTF-8"))
                : String.format(
                        "client_id=%s&client_secret=%s&code=%s&redirect_uri=%s&grant_type=authorization_code",
                        System.getenv("GOOGLE_CLIENT_ID"),
                        System.getenv("GOOGLE_CLIENT_SECRET"),
                        code,
                        URLEncoder.encode("https://gestprojetsswing-backend.onrender.com/api/auth/callback", "UTF-8"));

        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(tokenUrl))
                        .header("Accept", "application/json")
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        JSONObject responseBody = new JSONObject(response.body());
        if (!responseBody.has("access_token")) {
            throw new RuntimeException("Failed to get access token: " + responseBody);
        }
        return responseBody.getString("access_token");
    }

    private String buildAuthUrl(String provider, String state) {
        String clientId = System.getenv(provider.toUpperCase() + "_CLIENT_ID");
        String redirectUri = "https://gestprojetsswing-backend.onrender.com/api/auth/callback";

        String encodedState = Base64.getEncoder().encodeToString(new JSONObject()
                .put("provider", provider)
                .put("firebaseType", "signIn")
                .put("stateToken", state)
                .toString().getBytes());

        return provider.equals("github")
                ? String.format(
                        "https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user:email&state=%s",
                        clientId, redirectUri, encodedState)
                : String.format(
                        "https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=email profile&state=%s",
                        clientId, redirectUri, encodedState);
    }

    private void saveUserToFirestore(String uid, String email, String provider) throws Exception {
        Firestore db = FirestoreClient.getFirestore();
        DocumentSnapshot userDoc = db.collection("users").document(uid).get().get();

        if (!userDoc.exists()) {
            Map<String, Object> userData = new HashMap<>();
            userData.put("email", email);
            userData.put("createdAt", System.currentTimeMillis());
            userData.put("provider", provider);
            userData.put("lastLogin", System.currentTimeMillis());

            try {
                UserRecord userRecord = FirebaseAuth.getInstance().getUser(uid);
                if (userRecord.getDisplayName() != null) {
                    userData.put("fullName", userRecord.getDisplayName());
                }
            } catch (FirebaseAuthException e) {
                System.err.println("Could not get display name: " + e.getMessage());
            }

            db.collection("users").document(uid).set(userData);
        } else {
            db.collection("users").document(uid).update("lastLogin", System.currentTimeMillis());
        }
    }

    private UserRecord createOrUpdateUser(String provider, String email, String accessToken)
            throws FirebaseAuthException, IOException, InterruptedException {
        String uid = email.replaceAll("[^a-zA-Z0-9]", "_");

        try {
            return FirebaseAuth.getInstance().getUserByEmail(email);
        } catch (FirebaseAuthException e) {
            UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                    .setUid(uid)
                    .setEmail(email)
                    .setEmailVerified(true);

            if (provider.equals("google")) {
                request.setDisplayName(getGoogleUserName(accessToken));
            } else if (provider.equals("github")) {
                String name = getGitHubUserName(accessToken);
                if (name != null && !name.isEmpty()) {
                    request.setDisplayName(name);
                }
            }
            return FirebaseAuth.getInstance().createUser(request);
        }
    }

    private String getEmailFromProvider(String provider, String accessToken) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();

        if (provider.equals("github")) {
            HttpResponse<String> emailResponse = client.send(
                    HttpRequest.newBuilder()
                            .uri(URI.create("https://api.github.com/user/emails"))
                            .header("Authorization", "Bearer " + accessToken)
                            .header("Accept", "application/vnd.github+json")
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            JSONArray emails = new JSONArray(emailResponse.body());
            for (int i = 0; i < emails.length(); i++) {
                JSONObject emailObj = emails.getJSONObject(i);
                if (emailObj.getBoolean("primary")) {
                    return emailObj.getString("email");
                }
            }
            throw new RuntimeException("No primary email found for GitHub user");
        } else {
            HttpResponse<String> response = client.send(
                    HttpRequest.newBuilder()
                            .uri(URI.create("https://www.googleapis.com/oauth2/v3/userinfo"))
                            .header("Authorization", "Bearer " + accessToken)
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            return new JSONObject(response.body()).getString("email");
        }
    }

    private String getGoogleUserName(String accessToken) throws IOException, InterruptedException {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create("https://www.googleapis.com/oauth2/v3/userinfo"))
                        .header("Authorization", "Bearer " + accessToken)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        return new JSONObject(response.body()).optString("name", "User");
    }

    private String getGitHubUserName(String accessToken) throws IOException, InterruptedException {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create("https://api.github.com/user"))
                        .header("Authorization", "Bearer " + accessToken)
                        .header("Accept", "application/vnd.github+json")
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        return new JSONObject(response.body()).optString("name", "");
    }

    private String generateStateToken() {
        return UUID.randomUUID().toString();
    }

    private String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (jakarta.servlet.http.Cookie cookie : cookies) {
                if ("authToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    @Configuration
    public static class CorsConfig implements WebMvcConfigurer {

        @Override
        public void addCorsMappings(CorsRegistry registry) {
            registry.addMapping("/**")
                    .allowedOrigins("*")
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowedHeaders("*");
        }
    }
}
