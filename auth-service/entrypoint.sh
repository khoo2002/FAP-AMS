#!/bin/sh
set -e

# ensure keys dir exists
mkdir -p /keys

# generate keys if missing
if [ ! -f "/keys/private_key.pem" ] || [ ! -f "/keys/public_key.pem" ]; then
  echo "Generating RSA keypair in /keys"
  openssl genpkey -algorithm RSA -out /keys/private_key.pem -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout -in /keys/private_key.pem -out /keys/public_key.pem
  chmod 600 /keys/private_key.pem
  chmod 644 /keys/public_key.pem
else
  echo "Using existing keys in /keys"
fi

# exec the container CMD
exec "$@"
