FROM ubuntu:latest
LABEL authors="ahmet"

ENTRYPOINT ["top", "-b"]