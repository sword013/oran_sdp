# Use the MySQL 5.7 image as the base image
FROM mysql:5.7

# Set environment variables for MySQL credentials
ENV MYSQL_ROOT_PASSWORD=sdp
ENV MYSQL_DATABASE=sdp
ENV MYSQL_USER=sdp
ENV MYSQL_PASSWORD=sdp

# Copy SQL dump into the image
COPY sdp.sql /docker-entrypoint-initdb.d/

# Ensure the dump is executed during initialization
RUN chmod +x /docker-entrypoint-initdb.d/sdp.sql
