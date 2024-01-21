FROM maven:3.9.4-eclipse-temurin-21-alpine AS build
COPY . .
RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /authorization-server
ARG POSTGRES_USER
ARG POSTGRES_PASSWORD
ARG DATABASE_URL
COPY --from=build target/*.jar authorization-server.jar
EXPOSE 9000

ENTRYPOINT ["java", "-jar", "authorization-server.jar"]