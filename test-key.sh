#!/bin/sh

set -e
name="test-key"

encoder=""
if command -v gbasenc 2>&1 >/dev/null; then encoder="gbasenc"; fi
if command -v basenc 2>&1 >/dev/null; then encoder="basenc"; fi
if [ -z "${encoder}" ]; then
    echo "need to install basenc.  On MacOS do 'brew install coreutils', Linux 'apt install coreutils'"
    exit 1
fi


# if no public/private key file, generate it
if [ ! -f $name.pem ]; then
    echo info: generating fresh public/private key pair
    openssl genrsa -out $name.pem 2048
else
    echo info: re-using existing public/private key pair
fi

# generate public key file in PEM (for use in documentation)
openssl rsa -in $name.pem -pubout > $name.pub 2>/dev/null
# generate public key file in binary
openssl rsa -in $name.pem -pubout -outform der > $name.der 2>/dev/null


sha256hash=$(shasum -b -a 256 < $name.der | awk '{print $1}')
sha256url=$(echo -n $sha256hash | xxd -r -p | $encoder --base64url | tr -d "=")
sha256b32=$(echo -n $sha256hash | xxd -r -p | $encoder --base32 | tr -d "=")

echo "sha256 hash is          $sha256hash"
echo "sha256 base64url is     $sha256url"
echo "sha256 base32 is        $sha256b32"
echo 

sha512256hash=$(shasum -b -a 512256 < $name.der | awk '{print $1}')
sha512246url=$(echo -n $sha512256hash | xxd -r -p | $encoder --base64url | tr -d "=")
sha512256b32=$(echo -n $sha512256hash | xxd -r -p | $encoder --base32 | tr -d "=")

echo "sha512/256 hash is      $sha512256hash"
echo "sha512/256 base64url is $sha512246url"
echo "sha512/256 base32 is    $sha512256b32"

exit
