
# open for ! use
shopt -s extglob
rm -rf !(initfiles.sh|autogenerate.expect)
sudo cp /usr/lib/ssl/openssl.cnf ./
sed -in-place -e 's/= policy_match/= policy_anything/g' openssl.cnf
mkdir demoCA
cd demoCA
mkdir certs crl newcerts
touch index.txt serial
echo 1000 > serial
cd ..
expect autogenerate.expect
