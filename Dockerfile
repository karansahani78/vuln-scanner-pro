FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

COPY target/vuln-scanner-pro-1.0.0.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]
