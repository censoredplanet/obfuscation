FROM golang@sha256:c6a5b9308b3f3095e8fde83c8bf4d68bd101fce606c1a0a1394522542509dda9 AS builder
RUN git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel.git /webtunnel
ENV CGO_ENABLED=0
WORKDIR /webtunnel

RUN sed -i 's/ || ip.IsPrivate()//g' main/client/main.go
RUN go build -ldflags="-s -w" -o "build/client" gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/main/client

FROM debian@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

COPY --from=builder /webtunnel/build/client /usr/bin/webtunnel-client
COPY --from=builder /webtunnel/main/client/main.go /main.go

RUN apt-get update && apt-get install -y \
    curl gpg gpg-agent ca-certificates libcap2-bin --no-install-recommends

RUN curl https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import && \
    gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add - && \
    printf "deb https://deb.torproject.org/torproject.org bookworm main\n" >> /etc/apt/sources.list.d/tor.list

RUN apt-get update && apt-get install -y tor tor-geoipdb --no-install-recommends

COPY rootCA.pem /usr/local/share/ca-certificates/webtunnel-ca.crt
RUN update-ca-certificates

RUN rm -f /etc/tor/torrc && \
    chown debian-tor:debian-tor /etc/tor /var/log/tor

COPY torrc /etc/tor/torrc

USER debian-tor
CMD ["tor", "-f", "/etc/tor/torrc"]
