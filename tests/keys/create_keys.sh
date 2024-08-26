
for key_size in 1024 2048 4096
do
    echo "Generating keys with size: $key_size"
    openssl genrsa -out private_key_$key_size.pem -traditional $key_size
    openssl rsa -in private_key_$key_size.pem -out private_key_$key_size.der -outform DER
    openssl rsa -in private_key_$key_size.pem -pubout -out public_key_$key_size.der -outform DER
done