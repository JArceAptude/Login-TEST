FROM openjdk:17
WORKDIR '/app'
COPY ./target/security-0.0.1-SNAPSHOT.jar .
COPY . .
ENTRYPOINT ["java", "-jar", "./target/security-0.0.1-SNAPSHOT.jar"]
