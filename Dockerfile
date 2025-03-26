# Utilise une image Java officielle
FROM openjdk:21-jdk-slim

# Définit le répertoire de travail
WORKDIR /app

# Copie le projet dans le conteneur
COPY . .

# Installe Maven et construit le projet
RUN apt-get update && apt-get install -y maven
RUN mvn clean package -DskipTests

# Copie le JAR généré
COPY target/demo-0.0.1-SNAPSHOT.jar app.jar

# Expose le port
EXPOSE 8080

# Commande pour lancer l’application
ENTRYPOINT ["java", "-jar", "app.jar"]