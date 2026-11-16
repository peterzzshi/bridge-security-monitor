FROM gradle:9.9-jdk21 AS builder

WORKDIR /app

# Build context is the repo root (compose: context: .); the Gradle build reads
# schemas from $projectDir/../schemas.
COPY alerting-service/settings.gradle.kts alerting-service/build.gradle.kts ./
RUN gradle --no-daemon dependencies || true

COPY schemas ../schemas

COPY alerting-service/src ./src
RUN gradle --no-daemon clean installDist

FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=builder /app/build/install/alerting-service ./alerting-service

EXPOSE 8080

CMD ["./alerting-service/bin/alerting-service"]
