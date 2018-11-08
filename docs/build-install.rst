===================
Server Installation
===================

#. Start with a clean Ubuntu 18 LTS Server install.

#. Create lerc user::

    sudo adduser lerc

#. Git the lerc files in `/opt/`::

    cd /opt && sudo -E git clone https://github.com/seanmcfeely/lerc.git

#. Edit your ``/opt/lerc/lerc_server/etc/lerc_server.conf`` file for your environment.

  The lerc_server.conf is pre-configured to work on multiple interfaces, where one interface is internal and one is externally facing. If you are standing up the lerc server to work on one interface then you can remove the first VirtualHost entry entirely.

  The lerc_server.conf Apache configuration file that is included with lerc by default needs to have a few things for it to be completed. First, you must specifiy the server name(s) and paths to your certificate files. Below is an example configuration::

    <VirtualHost 0.0.0.0:443>
        ServerName lerc.local
        SSLEngine On
        SSLVerifyDepth 2
        SSLCertificateFile /opt/lerc/lerc_server/etc/ssl/lerc.local.public.cert.pem
        SSLCertificateKeyFile /opt/lerc/lerc_server/etc/ssl/lerc.local.private.key.pem
        SSLCertificateChainFile /opt/lerc/lerc_server/etc/ssl/ca-chain.cert.pem
        SSLCACertificateFile /opt/lerc/lerc_server/etc/ssl/ca-chain.cert.pem

        WSGIDaemonProcess control_server user=lerc group=lerc threads=2
        WSGIScriptAlias / /opt/lerc/lerc_server/lerc_server.wsgi
        WSGIChunkedRequest On

        <Directory /opt/lerc/lerc_server/>
            WSGIProcessGroup lerc_server
            WSGIApplicationGroup %{GLOBAL}
            WSGIScriptReloading On
            Allow from all
            Require all granted
            #Deny from all
            #Allow from 10.1.1.0/24
            SSLVerifyClient require
            SSLRequire %{SSL_CLIENT_S_DN_CN} eq "lerc.control.api.admin.whatever"
        </Directory>
    </VirtualHost>

    <VirtualHost 0.0.0.0:443>
        ServerName lerc.example.com
        SSLEngine On
        SSLVerifyDepth 2
        SSLCertificateFile /opt/lerc/lerc_server/etc/ssl/lerc.example.com.cert.pem
        SSLCertificateKeyFile /opt/lerc/lerc_server/etc/ssl/lerc.example.private.key.pem
        SSLCertificateChainFile /opt/lerc/lerc_server/etc/ssl/ca-chain.cert.pem
        SSLCACertificateFile /opt/lerc/lerc_server/etc/ssl/ca-chain.cert.pem

        WSGIDaemonProcess server user=lerc group=lerc threads=5
        WSGIScriptAlias / /opt/lerc/lerc_server/lerc_server.wsgi
        WSGIChunkedRequest On

        <Directory /opt/lerc/lerc_server/>
            WSGIProcessGroup server
            WSGIApplicationGroup %{GLOBAL}
            WSGIScriptReloading On
            Allow from all
            Require all granted
            SSLVerifyClient require
            SSLRequire %{SSL_CLIENT_S_DN_CN} eq "whatever.you.name.the.client.cert"
        </Directory>
        <Location /command>
            Order allow,deny
            Deny from all
            #SSLVerifyClient require
            #SSLRequire %{SSL_CLIENT_S_DN_CN} eq "probably.not.a.good.idea"
        </Location>
        SetEnv nokeepalive ssl-unclean-shutdown
    </VirtualHost>

#. Place your certificates at the paths specified in the config file above.

#. Set up your database.

   Edit the ``/opt/lerc/lerc_server/etc/schema.sql`` file.

     1. If you have more that one environment/comany, then duplicate the following line however many times you need to::

            INSERT INTO company_mapping SET name='<your organization/company/group name>';

     2. Change the "`password`" in the following command to something unique::

            GRANT ALL PRIVILEGES ON lerc . * TO 'lerc_user'@'localhost' IDENTIFIED BY 'password';

   Next, import the ``schema.sql`` file to configure mysql for lerc::

         sudo mysql < /opt/lerc/lerc_server/etc/schema.sql

#. Create this file ``/opt/lerc/lerc_server/etc/lerc_server.ini`` with the following defaults and supply the password you created above to the ``dbuserpass`` variable::

    [lerc_server]
    ; How many seconds a client will sleep before fetching 
    default_client_sleep=60
    chunk_size=8192
    ; if not specified by the analyst, the default location
    ; lerc.exe will write files
    default_client_dir=C:\Program Files (x86)\Integral Defense\
    dbserver=localhost
    dbuser=lerc_user
    dbuserpass=<fille me in>

#. Give lerc full permissions over ``/opt/lerc/``::

    sudo chown -R lerc:lerc lerc

#. Create a symlink from your configuration file to ``/etc/apache2/sites-available``. Example::

    cd /etc/apache2/sites-available && sudo ln -s /opt/lerc/lerc_server/etc/lerc_server.conf

#. Enable the apache ssl module and the lerc server site you symlinked to::

    sudo a2enmod ssl && sudo a2ensite lerc_server.conf

#. Reload Apache2::

    sudo service apache2 reload

Log Rotation
------------

You can configure logrotate to perform log rotation on the lerc server logs located at ``/opt/lerc/lerc_server/logs/server.log``.

All you need to do is create the following file ``/etc/logrotate.d/lerc_server`` and give it these contents::

    /opt/lerc/lerc_server/logs/server.log {
        daily
        missingok
        rotate 24
        notifempty
        su cybersecurity cybersecurity
        create 0640 cybersecurity cybersecurity
        postrotate
            service apache2 reload
        endscript
    }


