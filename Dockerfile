FROM alpine:3.12

RUN apk add -U ca-certificates tzdata mailcap && rm -Rf /var/cache/apk/*
COPY seleniferous /usr/bin

EXPOSE 4444
ENTRYPOINT ["/usr/bin/seleniferous", "-namespace", "selenosis"]