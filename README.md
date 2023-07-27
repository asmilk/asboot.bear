# asboot.bear

openssl genrsa -out rsa_private_key.pem 2048

cat rsa_private_key.pem

openssl rsa -in rsa_private_key.pem -out rsa_public_key.pem -pubout

cat rsa_public_key.pem

openssl pkcs8 -topk8 -in rsa_private_key.pem -out pkcs8_rsa_private_key.pem -nocrypt

cat pkcs8_rsa_private_key.pem