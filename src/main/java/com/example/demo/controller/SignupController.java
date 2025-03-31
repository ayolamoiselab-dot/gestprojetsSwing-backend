package com.example.demo.controller;

import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.auth.*;
import com.google.firebase.cloud.FirestoreClient;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

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