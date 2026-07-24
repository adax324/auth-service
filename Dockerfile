# Jar budowany lokalnie na hoście (`.\gradlew.bat bootJar`), nie w kontenerze — środowisko WSL2
# tej maszyny ma udokumentowany bug sieciowy (uszkadzanie pakietów TCP/TLS na wirtualnej karcie),
# przez co pobieranie zależności Gradle wewnątrz kontenera regularnie się wywala.
FROM eclipse-temurin:17-jre-alpine

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY build/libs/auth-service-1.0.0.jar app.jar

USER appuser

EXPOSE 8081

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-XX:InitialRAMPercentage=50.0", \
  "-jar", "app.jar"]
