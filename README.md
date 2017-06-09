 # openssl-engine-example

# Use Example
/usr/local/ssl/bin/openssl engine -t -c openssl_engine
echo "OpenSSL" | /usr/local/ssl/bin/openssl enc -e -engine openssl_engine -aes-128-ecb -a
echo "U2FsdGVkX19nk9QLKlyghKDWuCKcLxEPFLir81qR+2M=" | /usr/local/ssl/bin/openssl enc -d -engine openssl_engine -aes-128-ecb -a
echo whatever | /usr/local/ssl/bin/openssl dgst -engine openssl_engine -sha1
