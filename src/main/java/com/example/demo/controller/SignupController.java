package com.example.demo.controller;

import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.auth.*;
import com.google.firebase.cloud.FirestoreClient;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.net.URI;

@RestController
@RequestMapping("/api")
public class SignupController {

    private static final String FIREBASE_API_KEY = System.getenv("FIREBASE_API_KEY");
    private static final String GOOGLE_CLIENT_ID = System.getenv("GOOGLE_CLIENT_ID");
    private static final String GOOGLE_CLIENT_SECRET = System.getenv("GOOGLE_CLIENT_SECRET");
    private static final String GITHUB_CLIENT_ID = System.getenv("GITHUB_CLIENT_ID");
    private static final String GITHUB_CLIENT_SECRET = System.getenv("GITHUB_CLIENT_SECRET");

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
            sendVerificationEmail(email, verificationLink);

            return ResponseEntity.ok(new JSONObject()
                    .put("message", "User created, please verify your email.")
                    .put("uid", uid).toString());
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

    // Endpoint pour gérer le callback OAuth
    @GetMapping("/auth/callback")
    public ResponseEntity<Void> handleAuthCallback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error) {
        try {
            if (error != null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
            }

            if (code == null || state == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
            }

            // Le state contient le provider (google ou github)
            String provider = state;

            // Échanger le code contre un token et authentifier l'utilisateur
            JSONObject authResult = exchangeCodeForToken(provider, code);
            String uid = authResult.getString("uid");
            String fullName = authResult.optString("fullName", "Utilisateur");

            // Stocker les informations de l'utilisateur dans Firestore
            Firestore db = FirestoreClient.getFirestore();
            Map<String, Object> userData = new HashMap<>();
            userData.put("uid", uid);
            userData.put("fullName", fullName);
            userData.put("email", authResult.getString("email"));
            userData.put("createdAt", System.currentTimeMillis());
            userData.put("provider", provider);
            db.collection("users").document(uid).set(userData);

            // Rediriger vers le serveur local (NanoHTTPD) sur l'application Swing
            String redirectUrl = String.format(
                "http://localhost:8080/auth-success?uid=%s&fullName=%s",
                URLEncoder.encode(uid, StandardCharsets.UTF_8),
                URLEncoder.encode(fullName, StandardCharsets.UTF_8)
            );
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header("Location", redirectUrl)
                    .build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    // Méthode pour échanger le code OAuth contre un token et authentifier avec Firebase
    private JSONObject exchangeCodeForToken(String provider, String code) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String accessToken;
        String email;
        String fullName;

        if ("google".equals(provider)) {
            // Échanger le code contre un token pour Google
            String tokenUrl = "https://oauth2.googleapis.com/token";
            String redirectUri = "https://gestprojetsswing-backend.onrender.com/api/auth/callback";

            String body = String.format(
                "code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code",
                URLEncoder.encode(code, StandardCharsets.UTF_8),
                URLEncoder.encode(GOOGLE_CLIENT_ID, StandardCharsets.UTF_8),
                URLEncoder.encode(GOOGLE_CLIENT_SECRET, StandardCharsets.UTF_8),
                URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            );

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new Exception("Failed to exchange code for token: " + response.body());
            }

            JSONObject tokenResponse = new JSONObject(response.body());
            accessToken = tokenResponse.getString("access_token");

            // Récupérer les informations de l'utilisateur
            HttpRequest userRequest = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.googleapis.com/oauth2/v2/userinfo"))
                    .header("Authorization", "Bearer " + accessToken)
                    .GET()
                    .build();

            HttpResponse<String> userResponse = client.send(userRequest, HttpResponse.BodyHandlers.ofString());
            JSONObject userData = new JSONObject(userResponse.body());
            email = userData.getString("email");
            fullName = userData.optString("name", "Utilisateur");

        } else if ("github".equals(provider)) {
            // Échanger le code contre un token pour GitHub
            String tokenUrl = "https://github.com/login/oauth/access_token";
            String redirectUri = "https://gestprojetsswing-backend.onrender.com/api/auth/callback";

            String body = String.format(
                "client_id=%s&client_secret=%s&code=%s&redirect_uri=%s",
                URLEncoder.encode(GITHUB_CLIENT_ID, StandardCharsets.UTF_8),
                URLEncoder.encode(GITHUB_CLIENT_SECRET, StandardCharsets.UTF_8),
                URLEncoder.encode(code, StandardCharsets.UTF_8),
                URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
            );

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new Exception("Failed to exchange code for token: " + response.body());
            }

            JSONObject tokenResponse = new JSONObject(response.body());
            accessToken = tokenResponse.getString("access_token");

            // Récupérer les informations de l'utilisateur
            HttpRequest userRequest = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.github.com/user"))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/vnd.github.v3+json")
                    .GET()
                    .build();

            HttpResponse<String> userResponse = client.send(userRequest, HttpResponse.BodyHandlers.ofString());
            JSONObject userData = new JSONObject(userResponse.body());
            fullName = userData.optString("name", "Utilisateur");

            // Récupérer l'email de l'utilisateur (GitHub peut nécessiter une requête supplémentaire)
            HttpRequest emailRequest = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.github.com/user/emails"))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/vnd.github.v3+json")
                    .GET()
                    .build();

            HttpResponse<String> emailResponse = client.send(emailRequest, HttpResponse.BodyHandlers.ofString());
            JSONArray emails = new JSONArray(emailResponse.body());
            email = null;
            for (int i = 0; i < emails.length(); i++) {
                JSONObject emailObj = emails.getJSONObject(i);
                if (emailObj.getBoolean("primary") && emailObj.getBoolean("verified")) {
                    email = emailObj.getString("email");
                    break;
                }
            }
            if (email == null) {
                throw new Exception("Could not retrieve a verified email from GitHub.");
            }

        } else {
            throw new Exception("Unsupported provider: " + provider);
        }

        // Authentifier avec Firebase (créer ou mettre à jour l'utilisateur)
        FirebaseAuth auth = FirebaseAuth.getInstance();
        UserRecord userRecord;
        try {
            userRecord = auth.getUserByEmail(email);
        } catch (FirebaseAuthException e) {
            // Si l'utilisateur n'existe pas, le créer
            UserRecord.CreateRequest createRequest = new UserRecord.CreateRequest()
                    .setEmail(email)
                    .setDisplayName(fullName)
                    .setEmailVerified(true); // On suppose que l'email est vérifié par Google/GitHub
            userRecord = auth.createUser(createRequest);
        }

        JSONObject result = new JSONObject();
        result.put("uid", userRecord.getUid());
        result.put("fullName", fullName);
        result.put("email", email);
        return result;
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
}