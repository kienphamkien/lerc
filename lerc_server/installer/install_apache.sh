
# Configure Apache
#sudo apt-get -y install apache2
sudo a2enmod ssl
sudo a2ensite default-ssl
sudo a2enmod wsgi
sudo a2dissite default-ssl.conf
sudo a2dissite 000-default.conf

echo "Running the LERC Server with one interface or two? Choose one if you don't know what you want."
echo " -- One Interface: Both the LERC clients and analysts (control API) will access this server on the same interface."
echo " -- Two Interfaces: LERC Clients and analysts (control API) will access their features via different interfaces."
echo "Choose which interface configuration you want:"
select int in One Two; do
        case $int in
                One ) cp etc/examples/one_interface.lerc_server.example.conf etc/lerc.conf; break ;;
                Two ) cp etc/examples/two_interface.lerc_server.example.conf etc/lerc.conf; break ;;
        esac
done

echo "You chose to configure the LERC server with $int interfaces."

# modify server config to reflect correct configurations - LERC_SERVER_NAME LERC_CLIENT_CERT_ID
sed -e 's;^;s/LERC_SERVER_NAME/;' -e 's;$;/g;' ssl/.lerc_server_cn.txt > .lerc_server_cn.sed
sed -i -f .lerc_server_cn.sed etc/lerc.conf
rm .lerc_server_cn.sed
sed -e 's;^;s/LERC_CLIENT_CERT_ID/;' -e 's;$;/g;' ssl/.lerc_client_cn.txt > .lerc_client_cn.sed
sed -i -f .lerc_client_cn.sed etc/lerc.conf
rm .lerc_client_cn.sed
# LERC_ADMIN_CERT_ID
sed -e 's;^;s/LERC_ADMIN_CERT_ID/;' -e 's;$;/g;' ssl/.lerc_control_admin_cn.txt > .lerc_control_admin_cn.sed
sed -i -f .lerc_control_admin_cn.sed etc/lerc.conf
rm .lerc_control_admin_cn.sed

sudo ln -s /opt/lerc/lerc_server/etc/lerc.conf /etc/apache2/sites-available/lerc.conf && \
sudo a2ensite lerc && \
sudo systemctl restart apache2.service


exit 0

