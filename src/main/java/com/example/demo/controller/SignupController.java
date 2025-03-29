package com.example.demo.controller;

import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.cloud.FirestoreClient;
import com.example.demo.config.TemporaryUserStorage;
import com.google.firebase.auth.FirebaseToken;
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
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.google.firebase.auth.AuthCredential;
import com.google.firebase.auth.GoogleAuthProvider;
import com.google.firebase.auth.FacebookAuthProvider;
import com.google.firebase.auth.GithubAuthProvider;

@RestController
@RequestMapping("/api")
public class SignupController {

    private static final String FIREBASE_API_KEY = System.getenv("FIREBASE_API_KEY");

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

    // Nouvel endpoint pour récupérer les informations de l'utilisateur
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

    // Nouvel endpoint pour gérer la connexion (optionnel, car on utilise directement l'API Firebase)
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
        System.out.println("Verification email sent to " + toEmail);
    }

    @PostMapping("/social-auth")
    public ResponseEntity<String> socialAuth(@RequestBody String requestBody) {
        try {
            JSONObject json = new JSONObject(requestBody);
            String provider = json.getString("provider");
            String idToken = json.getString("idToken"); // Modifié de accessToken à idToken

            // Pas besoin de créer un AuthCredential si vous utilisez directement verifyIdToken
            FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(idToken);
            String uid = decodedToken.getUid();

            // Sauvegarder dans Firestore
            saveUserToFirestore(uid, decodedToken.getEmail(), provider);

            JSONObject response = new JSONObject();
            response.put("uid", uid);
            response.put("email", decodedToken.getEmail());
            response.put("fullName", decodedToken.getName()); // Peut être null

            return ResponseEntity.ok(response.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\": \"Erreur d'authentification: " + e.getMessage() + "\"}");
        }
    }

    @PostMapping("/auth/{provider}")
    public ResponseEntity<String> handleAuth(@PathVariable String provider, @RequestBody String code) {
        try {
            String accessToken = exchangeCodeForToken(provider, code);
            FirebaseToken firebaseToken = FirebaseAuth.getInstance().verifyIdToken(accessToken);

            saveUserToFirestore(firebaseToken.getUid(), firebaseToken.getEmail(), provider);

            return ResponseEntity.ok("{\"uid\": \"" + firebaseToken.getUid() + "\"}");
        } catch (Exception e) {
            return ResponseEntity.status(401).body("{\"error\": \"" + e.getMessage() + "\"}");
        }
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
                        "client_id=" + System.getenv(provider.toUpperCase() + "_CLIENT_ID")
                        + "&client_secret=" + System.getenv(provider.toUpperCase() + "_CLIENT_SECRET")
                        + "&code=" + code
                        + "&redirect_uri=https://gestprojetsswing-backend.onrender.com" // Doit correspondre à votre config
                ))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return new JSONObject(response.body()).getString("access_token");
    }

    @Configuration
    public class CorsConfig implements WebMvcConfigurer {

        @Override
        public void addCorsMappings(CorsRegistry registry) {
            registry.addMapping("/**")
                    .allowedOrigins("https://gestprojetsswing-backend.onrender.com") // Autoriser votre app Swing
                    .allowedMethods("GET", "POST");
        }
    }

    private void saveUserToFirestore(String uid, String email, String provider) throws Exception {
        Firestore db = FirestoreClient.getFirestore();
        DocumentSnapshot userDoc = db.collection("users").document(uid).get().get();

        if (!userDoc.exists()) {
            Map<String, Object> userData = new HashMap<>();
            userData.put("email", email);
            userData.put("createdAt", System.currentTimeMillis());
            userData.put("provider", provider);

            // Si vous voulez aussi stocker le nom (peut être null pour certains providers)
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
}
