FROM eclipse-temurin:17-jre
WORKDIR /opt/app
COPY target/security-demo-vuln.jar app.jar
# Path-traversal demo endpoint reads from here
RUN mkdir -p /opt/app/files && echo "hello.txt content" > /opt/app/files/hello.txt
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/opt/app/app.jar"]
