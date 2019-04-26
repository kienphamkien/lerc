#!/usr/bin/env bash
  
#
# installs and configures SSL certificates for ACE
#

# initialize root certificate directory
(
    cd ssl/root/ca && \
    rm -rf certs crl newcerts private index.txt* serial* && \
    mkdir -p certs crl newcerts private && \
    chmod 700 private && \
    touch index.txt && \
    echo 1000 > serial
) || { echo "directory prep for CA failed"; exit 1; }

# delete any old certs

# create a random password for the CA key
rm -f ssl/root/ca/.root_ca.pwd
tr -cd '[:alnum:]' < /dev/urandom | fold -w64 | head -n1 > ssl/root/ca/.root_ca.pwd
chmod 400 ssl/root/ca/.root_ca.pwd

# create root CA key (requires password)
( 
    cd ssl/root/ca && \
    openssl genrsa -aes256 -out private/ca.key.pem -passout file:.root_ca.pwd 4096 && \
    chmod 400 private/ca.key.pem
) || { echo "unable to create root CA key"; exit 1; }

# create root CA certificate
(
    cd ssl/root/ca && \
    openssl req -passin file:.root_ca.pwd -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.cert.pem -subj '/C=US/ST=KY/L=Covington/O=Integral/OU=Security/CN=localhost Root CA/emailAddress=lerc@localhost' && \
    chmod 444 certs/ca.cert.pem
) || { echo "unable to create root CA cert"; exit 1; }

# prepare intermediate directory
(
    cd ssl/root/ca/intermediate && \
    rm -rf certs crl csr newcerts private index.txt* serial* && \
    mkdir -p certs crl csr newcerts private && \
    chmod 700 private && \
    touch index.txt && \
    echo 1000 > serial && \
    echo 1000 > crlnumber
) || { echo "directory prep for intermediate failed"; exit 1; }

# create a random password for the intermediate key
rm -f ssl/root/ca/.intermediate_ca.pwd
tr -cd '[:alnum:]' < /dev/urandom | fold -w64 | head -n1 > ssl/root/ca/.intermediate_ca.pwd
chmod 400 ssl/root/ca/.intermediate_ca.pwd

# create intermediate key
(
    cd ssl/root/ca && \
    openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem -passout file:.intermediate_ca.pwd 4096 && \
    chmod 400 intermediate/private/intermediate.key.pem
) || { echo "unable to create intermediate key"; exit 1; }

# create intermediate CA
(
    cd ssl/root/ca && \
    openssl req -passin file:.intermediate_ca.pwd -config intermediate/openssl.cnf -new -sha256 -key intermediate/private/intermediate.key.pem -out intermediate/csr/intermediate.csr.pem -subj '/C=US/ST=KY/L=Covington/O=Integral/OU=Security/CN=localhost Intermediate CA/emailAddress=lerc@localhost' && \
    openssl ca -batch -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem -passin file:.root_ca.pwd && \
    chmod 444 intermediate/certs/intermediate.cert.pem && \
    openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem && \
    cat certs/ca.cert.pem intermediate/certs/intermediate.cert.pem > intermediate/certs/ca-chain.cert.pem && \
    chmod 444 intermediate/certs/ca-chain.cert.pem
) || { echo "unable to create intermediate cert"; exit 1; }


# create the SSL certificates for localhost
lerc_server_cn="lerc.localhost"
echo "Do you wish specify the Common Name for your server certificate? The default is 'lerc.localhost'."
select cname in Yes No; do
        case ${cname} in
                Yes ) read -p "Enter the name: " lerc_server_cn ; break ;;
                No ) break ;;
        esac
done
echo $lerc_server_cn > ssl/.lerc_server_cn.txt

# Attempt to get the current internet facing IP of this server
lerc_server_ip=$(curl -s http://whatismyip.akamai.com/)
echo "The internet IP address of this server appears to be '$lerc_server_ip'"
echo "Do you wish specify a different IP address for your server certificate?"
select ipaddr in Yes No; do
        case ${ipaddr} in
                Yes ) read -p "Enter the IP: " lerc_server_ip ; break ;;
                No ) break ;;
        esac
done
echo $lerc_server_ip > ssl/.lerc_server_ip.txt
(
    cd ssl/root/ca && \
    cat intermediate/openssl.cnf > intermediate/openssl.temp.cnf && \
    echo "DNS.1 = ${lerc_server_cn}" >> intermediate/openssl.temp.cnf && \
    echo "IP.1 = ${lerc_server_ip}" >> intermediate/openssl.temp.cnf && \
    openssl genrsa -out intermediate/private/localhost.key.pem 2048 && \
    chmod 400 intermediate/private/localhost.key.pem && \
    openssl req -config intermediate/openssl.temp.cnf -key intermediate/private/localhost.key.pem -new -sha256 -out intermediate/csr/localhost.csr.pem -subj "/C=US/ST=KY/L=Covington/O=Integral/OU=Security/CN=${lerc_server_cn}/emailAddress=lerc@localhost" && \
    openssl ca -passin file:.intermediate_ca.pwd -batch -config intermediate/openssl.temp.cnf -extensions server_cert -days 3649 -notext -md sha256 -in intermediate/csr/localhost.csr.pem -out intermediate/certs/localhost.cert.pem
    chmod 444 intermediate/certs/localhost.cert.pem
) || { echo "unable to create SSL certificate for localhost"; exit 1; }

# copy them for LERC server
# create the symlink for the CA root cert bundle
(cd ssl && rm -f ca-chain.cert.pem && ln -s root/ca/intermediate/certs/ca-chain.cert.pem .)
(cd ssl && rm -f localhost.cert.pem && ln -s root/ca/intermediate/certs/localhost.cert.pem lerc.localhost.cert.pem)
(cd ssl && rm -f localhost.key.pem && ln -s root/ca/intermediate/private/localhost.key.pem lerc.localhost.key.pem)

# Make LERC client certs
echo "Creating client verification cert.."
# XXX Make LERC_CLIENT_CERT_ID configurable here later?
lerc_client_cn='lerc.client'
echo $lerc_client_cn > ssl/.lerc_client_cn.txt
(
    cd ssl/root/ca && \
    cat intermediate/openssl.cnf > intermediate/openssl.temp.cnf && \
    echo "DNS.1 = ${lerc_client_cn}" >> intermediate/openssl.temp.cnf && \
    openssl genrsa -out intermediate/private/lerc.client.key.pem 2048 && \
    chmod 400 intermediate/private/lerc.client.key.pem && \
    openssl req -config intermediate/openssl.temp.cnf -key intermediate/private/lerc.client.key.pem -new -sha256 -out intermediate/csr/lerc.client.csr.pem -subj "/C=US/OU=Security/CN=${lerc_client_cn}/emailAddress=support@integraldefense.com" && \
    openssl ca -passin file:.intermediate_ca.pwd -batch -config intermediate/openssl.temp.cnf -extensions usr_cert -days 3649 -notext -md sha256 -in intermediate/csr/lerc.client.csr.pem -out intermediate/certs/lerc.client.cert.pem && \
    chmod 444 intermediate/certs/lerc.client.cert.pem && \
    openssl pkcs12 -export -out intermediate/certs/lerc.client.pfx -inkey intermediate/private/lerc.client.key.pem -in intermediate/certs/lerc.client.cert.pem -certfile intermediate/certs/ca-chain.cert.pem -passout pass: 
) || { echo "unable to create SSL certificate for LERC clients"; exit 1; }

# For convenience, put what the client will need here
( cd ssl && rm -rf client && mkdir client )

(
    cd ssl && \
    ln -s ../root/ca/intermediate/certs/lerc.client.pfx client/. && \
    ln -s ../root/ca/intermediate/certs/ca-chain.cert.pem client/lerc.ca.pem
) || { echo "unable to create symlinks for LERC client certs"; exit 1; }

echo "Client will need the generated ssl/client/lerc.client.pfx and the ca-chain copy at ssl/client/lerc.ca.pem in the clients home dir."


# Make admin cert 
echo "Creating LERC Control admin cert.."
# XXX Allow user to specify name of cert?
lerc_control_admin_cn='lerc.control.admin'
echo $lerc_control_admin_cn > ssl/.lerc_control_admin_cn.txt
(
    cd ssl/root/ca && \
    cat intermediate/openssl.cnf > intermediate/openssl.temp.cnf && \
    echo "DNS.1 = ${lerc_control_admin_cn}"  >> intermediate/openssl.temp.cnf && \
    openssl genrsa -out intermediate/private/lerc.control.key.pem 2048 && \
    chmod 400 intermediate/private/lerc.control.key.pem && \
    openssl req -config intermediate/openssl.temp.cnf -key intermediate/private/lerc.control.key.pem -new -sha256 -out intermediate/csr/lerc.control.csr.pem -subj "/C=US/OU=Security/CN=${lerc_control_admin_cn}/emailAddress=support@integraldefense.com" && \
    openssl ca -passin file:.intermediate_ca.pwd -batch -config intermediate/openssl.temp.cnf -extensions usr_cert -days 3649 -notext -md sha256 -in intermediate/csr/lerc.control.csr.pem -out intermediate/certs/lerc.control.cert.pem && \
    chmod 444 intermediate/certs/lerc.control.cert.pem
) || { echo "unable to create SSL certificate for LERC clients"; exit 1; }

# Symlink convenience
(cd ssl && rm -rf admin && mkdir admin )
(
    cd ssl && \
    ln -s ../root/ca/intermediate/private/lerc.control.key.pem admin/. && \
    ln -s ../root/ca/intermediate/certs/lerc.control.cert.pem admin/.
) || { echo "unable to create symlinks for analyst admin certs"; exit 1; }
