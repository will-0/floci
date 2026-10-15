FROM alpine:3.21
RUN apk add --no-cache nftables iproute2 socat curl tcpdump
CMD ["sleep", "2147483647"]
