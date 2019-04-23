
echo "Installing and configuring LERC control for local use, from source."
( cd /opt/lerc/ && sudo python3 setup.py install ) || { echo "lerc-control source install faild"; exit 1; }
( cd /etc/ && sudo mkdir lerc_control )

touch lerc.ini
(
    echo "[default"] > lerc.ini && \
    echo "server=lerc.localhost" >> lerc.ini && \
    echo "client_cert=/opt/lerc/lerc_server/ssl/admin/lerc.control.cert.pem" >> lerc.ini && \
    echo "client_key=/opt/lerc/lerc_server/ssl/admin/lerc.control.key.pem" >> lerc.ini && \
    echo "server_ca_cert=/opt/lerc/lerc_server/ssl/ca-chain.cert.pem" >> lerc.ini
    ) || { echo "Failed to write lerc.ini"; exit 1;}

sudo cp lerc.ini /etc/lerc_control/lerc.ini
rm lerc.ini
