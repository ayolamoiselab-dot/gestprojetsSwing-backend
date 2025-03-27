package com.example.demo.controller;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.cloud.firestore.QuerySnapshot;
import com.google.firebase.cloud.FirestoreClient;
import java.util.ArrayList;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ProjectController {

    @PostMapping("/projects")
    public ResponseEntity<String> createProject(@RequestBody String projectData) {
        try {
            JSONObject projectJson = new JSONObject(projectData);

            // Récupérer les données du projet
            String projectName = projectJson.getString("projectName");
            String description = projectJson.getString("description");
            String type = projectJson.getString("type");
            String uid = projectJson.getString("uid");
            String durationUnit = projectJson.optString("durationUnit", null);
            int durationValue = projectJson.optInt("durationValue", 0);
            long startDate = projectJson.optLong("startDate", 0);
            long endDate = projectJson.optLong("endDate", 0);

            // Créer un document dans Firestore
            Firestore db = FirestoreClient.getFirestore();
            Map<String, Object> projectMap = new HashMap<>();
            projectMap.put("projectName", projectName);
            projectMap.put("description", description);
            projectMap.put("type", type);
            projectMap.put("uid", uid); // Référence à l'utilisateur
            projectMap.put("createdAt", System.currentTimeMillis());
            if (durationUnit != null) {
                projectMap.put("durationUnit", durationUnit);
                projectMap.put("durationValue", durationValue);
            }
            if (startDate != 0) {
                projectMap.put("startDate", startDate);
            }
            if (endDate != 0) {
                projectMap.put("endDate", endDate);
            }

            // Ajouter le projet à la collection "projects"
            String projectId = db.collection("projects").document().getId();
            db.collection("projects").document(projectId).set(projectMap);

            JSONObject response = new JSONObject();
            response.put("message", "Projet créé avec succès.");
            response.put("projectId", projectId);
            return ResponseEntity.ok(response.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\": \"Erreur serveur: " + e.getMessage() + "\"}");
        }
    }

    @GetMapping("/projects/{uid}")
    public ResponseEntity<String> getProjectsByUser(@PathVariable("uid") String uid) {
        try {
            Firestore db = FirestoreClient.getFirestore();
            List<Map<String, Object>> projectsList = new ArrayList<>();
            QuerySnapshot querySnapshot = db.collection("projects")
                    .whereEqualTo("uid", uid)
                    .get()
                    .get();

            for (QueryDocumentSnapshot document : querySnapshot) {
                Map<String, Object> projectData = document.getData();
                projectData.put("projectId", document.getId());
                projectsList.add(projectData);
            }

            JSONObject response = new JSONObject();
            response.put("projects", projectsList);
            return ResponseEntity.ok(response.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\": \"Erreur serveur: " + e.getMessage() + "\"}");
        }
    }
}
