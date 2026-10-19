#!/bin/bash
set -euo pipefail
umask 077
cd /out
test ! -e ca.key
openssl req -new -x509 -nodes -newkey rsa:2048 -days 365 -subj /CN=Salmora-local-CA -keyout ca.key -out ca.crt 2>/dev/null
openssl req -new -nodes -newkey rsa:2048 -subj /CN=localhost -keyout server.key -out server.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,DNS:app-postgres,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extfile server.ext 2>/dev/null
rm server.csr server.ext
echo PORTABLE_LOCAL_CERTIFICATE_CREATED
