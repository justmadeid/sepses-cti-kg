# Apache Jena Fuseki 5.6.0 dari rilis resmi Apache (bukan image pihak ketiga).
# Integritas unduhan diperiksa dengan SHA-512 resmi yang ditanam di bawah.
FROM eclipse-temurin:21-jre
ARG FUSEKI_VERSION=5.6.0
ARG FUSEKI_SHA512=19bfa2eafc6d349f6d98129c587e545656c15659d116c727770f1d65092938767e7b0ed3976355f47ac753560b37fc4872e6e4e53437c3cc2330edef3d56cf46
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o /tmp/fuseki.zip https://archive.apache.org/dist/jena/binaries/apache-jena-fuseki-${FUSEKI_VERSION}.zip \
 && echo "${FUSEKI_SHA512}  /tmp/fuseki.zip" | sha512sum -c - \
 && unzip -q /tmp/fuseki.zip -d /opt && mv /opt/apache-jena-fuseki-${FUSEKI_VERSION} /opt/fuseki && rm /tmp/fuseki.zip
ENV FUSEKI_HOME=/opt/fuseki FUSEKI_BASE=/fuseki
WORKDIR /opt/fuseki
EXPOSE 3030
CMD ["/opt/fuseki/fuseki-server", "--config=/fuseki/config.ttl"]
