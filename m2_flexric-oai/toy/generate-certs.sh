#!/bin/bash

set -e

CERT_DIR=certs
mkdir -p "$CERT_DIR"

echo "[*] Generating CA..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
    -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=My Root CA" \
    -out "$CERT_DIR/ca.crt"

echo "[*] Generating Server key and CSR..."
openssl genrsa -out "$CERT_DIR/server.key" 2048
openssl req -new -key "$CERT_DIR/server.key" \
    -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=mtls-gateway" \
    -out "$CERT_DIR/server.csr"

echo "[*] Signing Server cert with CA..."
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/server.crt" -days 825 -sha256

echo "[*] Generating Client key and CSR..."
openssl genrsa -out "$CERT_DIR/client.key" 2048
openssl req -new -key "$CERT_DIR/client.key" \
    -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=mtls-client" \
    -out "$CERT_DIR/client.csr"

echo "[*] Signing Client cert with CA..."
openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/client.crt" -days 825 -sha256

echo "[*] All certs are ready in ./$CERT_DIR"
