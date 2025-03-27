# Utilise une image Java officielle
FROM openjdk:21-jdk-slim

# Définit le répertoire de travail
WORKDIR /app

# Copie le projet dans le conteneur
COPY . .

# Installe Maven
RUN apt-get update && apt-get install -y maven

# Construit le projet avec Maven
RUN mvn clean package -DskipTests

# Trouve le JAR généré dynamiquement et le copie dans app.jar
RUN cp target/*.jar app.jar

# Expose le port
EXPOSE 8080

# Commande pour lancer l’application
ENTRYPOINT ["java", "-jar", "app.jar"]