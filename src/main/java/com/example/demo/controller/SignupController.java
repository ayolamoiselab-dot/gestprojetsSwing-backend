package com.example.demo.controller;

import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.auth.*;
import com.google.firebase.cloud.FirestoreClient;
import com.example.demo.config.TemporaryUserStorage;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.UUID;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api")
public class SignupController {

    private static final String FIREBASE_API_KEY = System.getenv("FIREBASE_API_KEY");
    // Classe interne pour gérer les credentials GitHub


    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody String requestBody) {
        try {
            JSONObject json = new JSONObject(requestBody);
            String fullName = json.getString("fullName");
            String email = json.getString("email");
            String password = json.getString("password");

            UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                    .setEmail(email)
                    .setPassword(password)
                    .setDisplayName(fullName)
                    .setEmailVerified(false);

            UserRecord userRecord = FirebaseAuth.getInstance().createUser(request);
            String uid = userRecord.getUid();

            String verificationLink = FirebaseAuth.getInstance().generateEmailVerificationLink(email) + "&uid=" + uid;
            TemporaryUserStorage.store(uid, fullName, email, password);

            sendVerificationEmail(email, verificationLink);

            JSONObject responseJson = new JSONObject();
            responseJson.put("message", "User created, please verify your email.");
            responseJson.put("uid", uid);
            return ResponseEntity.ok(responseJson.toString());
        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(400).body("{\"error\": \"Error creating user: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\": \"Server error: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam("uid") String uid, @RequestParam("oobCode") String oobCode) {
        try {
            boolean isVerified = verifyEmailWithOobCode(oobCode);

            if (!isVerified) {
                return ResponseEntity.status(400).body("{\"error\": \"Invalid or expired verification link.\"}");
            }

            UserRecord.UpdateRequest updateRequest = new UserRecord.UpdateRequest(uid)
                    .setEmailVerified(true);
            FirebaseAuth.getInstance().updateUser(updateRequest);

            UserRecord userRecord = FirebaseAuth.getInstance().getUser(uid);
            if (userRecord.isEmailVerified()) {
                TemporaryUserStorage.UserData userData = TemporaryUserStorage.get(uid);
                if (userData == null) {
                    return ResponseEntity.status(400).body("{\"error\": \"User data not found.\"}");
                }

                Firestore db = FirestoreClient.getFirestore();
                Map<String, Object> userMap = new HashMap<>();
                userMap.put("fullName", userData.getFullName());
                userMap.put("email", userData.getEmail());
                userMap.put("createdAt", System.currentTimeMillis());

                db.collection("users").document(uid).set(userMap);
                TemporaryUserStorage.remove(uid);

                return ResponseEntity.ok("{\"message\": \"Email verified, user created in Firestore.\"}");
            } else {
                return ResponseEntity.status(400).body("{\"error\": \"Email not yet verified.\"}");
            }
        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(400).body("{\"error\": \"Error verifying user: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\": \"Server error: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/check-verification-status")
    public ResponseEntity<String> checkVerificationStatus(@RequestParam("uid") String uid) {
        try {
            UserRecord userRecord = FirebaseAuth.getInstance().getUser(uid);
            JSONObject responseJson = new JSONObject();
            responseJson.put("status", userRecord.isEmailVerified() ? "verified" : "pending");
            return ResponseEntity.ok(responseJson.toString());
        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(400).body("{\"error\": \"User not found: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/user/{uid}")
    public ResponseEntity<String> getUser(@PathVariable("uid") String uid) {
        try {
            Firestore db = FirestoreClient.getFirestore();
            DocumentSnapshot document = db.collection("users").document(uid).get().get();
            if (document.exists()) {
                Map<String, Object> userData = document.getData();
                JSONObject responseJson = new JSONObject();
                responseJson.put("uid", uid);
                responseJson.put("fullName", userData.get("fullName"));
                responseJson.put("email", userData.get("email"));
                responseJson.put("createdAt", userData.get("createdAt"));
                return ResponseEntity.ok(responseJson.toString());
            } else {
                return ResponseEntity.status(404).body("{\"error\": \"User not found.\"}");
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\": \"Server error: " + e.getMessage() + "\"}");
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
            JSONObject signInPayload = new JSONObject();
            signInPayload.put("email", email);
            signInPayload.put("password", password);
            signInPayload.put("returnSecureToken", true);

            HttpRequest signInRequest = HttpRequest.newBuilder()
                    .uri(URI.create(signInUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(signInPayload.toString()))
                    .build();
            HttpResponse<String> signInResponse = client.send(signInRequest, HttpResponse.BodyHandlers.ofString());

            if (signInResponse.statusCode() != 200) {
                return ResponseEntity.status(401).body("{\"error\": \"Invalid email or password.\"}");
            }

            JSONObject signInJson = new JSONObject(signInResponse.body());
            String uid = signInJson.getString("localId");

            JSONObject responseJson = new JSONObject();
            responseJson.put("message", "Login successful.");
            responseJson.put("uid", uid);
            return ResponseEntity.ok(responseJson.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\": \"Server error: " + e.getMessage() + "\"}");
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

            JSONObject response = new JSONObject();
            response.put("uid", uid);
            response.put("email", decodedToken.getEmail());
            response.put("fullName", decodedToken.getName());

            return ResponseEntity.ok(response.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\": \"Erreur d'authentification: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/auth/callback")
    public void handleCallback(
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            HttpServletResponse response) throws IOException {

        try {
            String decodedState = new String(Base64.getDecoder().decode(state));
            JSONObject stateJson = new JSONObject(decodedState);
            String provider = stateJson.getString("provider");

            String accessToken = exchangeCodeForToken(provider, code);
            String uid = createFirebaseUser(provider, accessToken);
            String customToken = FirebaseAuth.getInstance().createCustomToken(uid);

            jakarta.servlet.http.Cookie authCookie = new jakarta.servlet.http.Cookie("authToken", customToken);
            authCookie.setHttpOnly(true);
            authCookie.setSecure(true);
            authCookie.setPath("/");
            authCookie.setMaxAge(60 * 60 * 24);
            response.addCookie(authCookie);

            String redirectUrl = String.format(
                "https://gestprojetsswing-backend.onrender.com/api/auth/complete?token=%s&uid=%s",
                URLEncoder.encode(customToken, "UTF-8"),
                URLEncoder.encode(uid, "UTF-8")
            );
            response.sendRedirect(redirectUrl);
        } catch (Exception e) {
            String errorRedirect = String.format(
                "https://gestprojetsswing-backend.onrender.com/api/auth/complete?error=%s",
                URLEncoder.encode(e.getMessage(), "UTF-8")
            );
            response.sendRedirect(errorRedirect);
        }
    }

    @GetMapping("/auth/complete")
    public ResponseEntity<String> authComplete(
        @RequestParam(value = "token", required = false) String token,
        @RequestParam(value = "uid", required = false) String uid,
        @RequestParam(value = "error", required = false) String error) {
        
        if (error != null) {
            return ResponseEntity.status(400).body("{\"error\": \"" + error + "\"}");
        }
        
        JSONObject response = new JSONObject();
        response.put("status", "success");
        response.put("token", token);
        response.put("uid", uid);
        return ResponseEntity.ok(response.toString());
    }

    @GetMapping("/auth/{provider}")
    public void authRedirect(@PathVariable String provider, HttpServletResponse response) throws IOException {
        try {
            String state = generateStateToken();
            String authUrl = buildAuthUrl(provider, state);
            response.sendRedirect(authUrl);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Erreur lors de la génération de l'URL: " + e.getMessage());
        }
    }

    @GetMapping("/check-auth-status")
    public ResponseEntity<String> checkAuthStatus(HttpServletRequest request) {
        try {
            String idToken = extractToken(request);

            if (idToken != null) {
                FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(idToken);
                String uid = decodedToken.getUid();

                Firestore db = FirestoreClient.getFirestore();
                DocumentSnapshot userDoc = db.collection("users").document(uid).get().get();

                JSONObject response = new JSONObject();
                response.put("isAuthenticated", true);
                response.put("uid", uid);

                if (userDoc.exists()) {
                    Map<String, Object> userData = userDoc.getData();
                    response.put("fullName", userData.getOrDefault("fullName", "User"));
                } else {
                    response.put("fullName", "User");
                }

                return ResponseEntity.ok(response.toString());
            }

            return ResponseEntity.ok("{\"isAuthenticated\": false}");
        } catch (Exception e) {
            return ResponseEntity.ok("{\"isAuthenticated\": false}");
        }
    }

    // Méthodes utilitaires privées
    private boolean verifyEmailWithOobCode(String oobCode) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String url = "https://identitytoolkit.googleapis.com/v1/accounts:update?key=" + FIREBASE_API_KEY;
        JSONObject payload = new JSONObject();
        payload.put("oobCode", oobCode);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode() == 200;
    }

    private void sendVerificationEmail(String toEmail, String verificationLink) throws MessagingException {
        String host = "smtp.gmail.com";
        String from = "moiseayola6@gmail.com";
        String password = System.getenv("GMAIL_PASSWORD");

        Properties properties = new Properties();
        properties.put("mail.smtp.host", host);
        properties.put("mail.smtp.port", "587");
        properties.put("mail.smtp.auth", "true");
        properties.put("mail.smtp.starttls.enable", "true");

        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(from, password);
            }
        });

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(from));
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

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUrl))
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "client_id=" + System.getenv(provider.toUpperCase() + "_CLIENT_ID") +
                        "&client_secret=" + System.getenv(provider.toUpperCase() + "_CLIENT_SECRET") +
                        "&code=" + code +
                        "&redirect_uri=https://gestprojetsswing-backend.onrender.com"
                ))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return new JSONObject(response.body()).getString("access_token");
    }

    private String buildAuthUrl(String provider, String state) {
        String clientId = System.getenv(provider.toUpperCase() + "_CLIENT_ID");
        String redirectUri = "https://gestprojetsswing-backend.onrender.com/api/auth/callback";

        Map<String, String> stateData = new HashMap<>();
        stateData.put("provider", provider);
        stateData.put("firebaseType", "signIn");
        stateData.put("stateToken", state);

        String encodedState = Base64.getEncoder().encodeToString(
                new JSONObject(stateData).toString().getBytes()
        );

        return provider.equalsIgnoreCase("github")
                ? "https://github.com/login/oauth/authorize?client_id=" + clientId +
                  "&redirect_uri=" + redirectUri +
                  "&scope=user:email" +
                  "&state=" + encodedState
                : "https://accounts.google.com/o/oauth2/v2/auth?client_id=" + clientId +
                  "&redirect_uri=" + redirectUri +
                  "&response_type=code" +
                  "&scope=email profile" +
                  "&state=" + encodedState;
    }

    private void saveUserToFirestore(String uid, String email, String provider) throws Exception {
        Firestore db = FirestoreClient.getFirestore();
        DocumentSnapshot userDoc = db.collection("users").document(uid).get().get();

        if (!userDoc.exists()) {
            Map<String, Object> userData = new HashMap<>();
            userData.put("email", email);
            userData.put("createdAt", System.currentTimeMillis());
            userData.put("provider", provider);

            try {
                UserRecord userRecord = FirebaseAuth.getInstance().getUser(uid);
                if (userRecord.getDisplayName() != null) {
                    userData.put("fullName", userRecord.getDisplayName());
                }
            } catch (FirebaseAuthException e) {
                System.out.println("Could not get display name: " + e.getMessage());
            }

            db.collection("users").document(uid).set(userData);
        }
    }

    private String createFirebaseUser(String provider, String accessToken) throws FirebaseAuthException, IOException, InterruptedException {
        String email = getEmailFromProvider(provider, accessToken);
        String uid = email.replaceAll("[^a-zA-Z0-9]", "_");

        try {
            UserRecord userRecord = FirebaseAuth.getInstance().getUserByEmail(email);
            return userRecord.getUid();
        } catch (FirebaseAuthException e) {
            UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                    .setUid(uid)
                    .setEmail(email)
                    .setEmailVerified(true);

            if (provider.equalsIgnoreCase("google")) {
                request.setDisplayName(getGoogleUserName(accessToken));
            }

            UserRecord userRecord = FirebaseAuth.getInstance().createUser(request);
            return userRecord.getUid();
        }
    }

    private String getEmailFromProvider(String provider, String accessToken) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        String userInfoUrl = provider.equalsIgnoreCase("github")
                ? "https://api.github.com/user"
                : "https://www.googleapis.com/oauth2/v3/userinfo";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(userInfoUrl))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        JSONObject userInfo = new JSONObject(response.body());

        return userInfo.getString("email");
    }

    private String getGoogleUserName(String accessToken) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.googleapis.com/oauth2/v3/userinfo"))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        JSONObject userInfo = new JSONObject(response.body());

        return userInfo.optString("name", "User");
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
    public class CorsConfig implements WebMvcConfigurer {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            registry.addMapping("/**")
                    .allowedOrigins("*")
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowedHeaders("*");
        }
    }
}