FROM maven:3.9.4-eclipse-temurin-21-alpine AS build
COPY . .
RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /authorization-server
ARG DB_USERNAME
ARG DB_PASSWORD
ARG DB_URL
COPY --from=build target/*.jar authorization-server.jar
EXPOSE 9000

ENTRYPOINT ["java", "-jar", "authorization-server.jar"]