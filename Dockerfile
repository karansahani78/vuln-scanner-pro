# ===============================
# Build stage
# ===============================
FROM eclipse-temurin:17-jdk-jammy AS build

WORKDIR /app

COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline

COPY src src
RUN ./mvnw clean package -DskipTests

# ===============================
# Runtime stage
# ===============================
FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

COPY --from=build /app/target/vuln-scanner-pro-1.0.0.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]
