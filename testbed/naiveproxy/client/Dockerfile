FROM pocat/naiveproxy@sha256:ae6dff0ca7bef5d9228ec85f366038f55d430c61245b8295c0479e351f5b0fbf 

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libnss3-tools \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /root/.pki/nssdb \
    && chmod 700 /root/.pki/nssdb

RUN certutil -d sql:/root/.pki/nssdb -N --empty-password

COPY rootCA.pem /tmp/root.crt

RUN ls -l /tmp/root.crt && \
    certutil -d sql:/root/.pki/nssdb -A -t "C,," -n "NaiveRoot" -i /tmp/root.crt

RUN cp /tmp/root.crt /usr/local/share/ca-certificates/naive-root.crt && \
    update-ca-certificates
