FROM debian:13-slim

RUN apt-get update && apt-get -y install make gcc-mingw-w64-x86-64

COPY . /srv

WORKDIR /srv

RUN make \
  && sha256sum tir.exe > SHA256SUMS
