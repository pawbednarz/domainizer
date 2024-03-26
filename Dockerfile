FROM maven AS build
COPY . /home/maven/src
WORKDIR /home/maven/src
RUN mvn package

FROM drwetter/testssl.sh
COPY . /app/

FROM openjdk:11-jre-slim
EXPOSE 8080
RUN mkdir /app
COPY --from=build /home/maven/src/target/Domainzer-1.0-SNAPSHOT.jar /app/domainizer.jar
ENTRYPOINT ["java", "-jar","/app/domainizer.jar"]
