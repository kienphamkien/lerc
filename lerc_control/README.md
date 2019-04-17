# Live Endpoint Response Client Control

LERC Control provides utilities for interacting and controlling clients (via the LERC Server API) to perform live response and administrative actions. LERC Control can be used as a library or the 'lerc_ui' script is made available for global use when installed with pip3. 
### Features

+ Upload files from clients
+ Contain clients with the windows firewall (configurable firewall rules)
+ Download files to the clients
+ Run commands on the clients
+ Perform scripted routines
+ Create scripted routines and save them for future use
+ Perform complex collections routines via custom, extendable modules
+ Perform remediation actions (file/registry deletions, service deletion, schedule task deletion, process killing) - also extendable module format
+ Query the LERC Server for client statuses and client command history

## Getting Started

You can install lerc_control with pip3:

    pip3 install lerc-control

Once you have a working LERC Server and have generated your analyst certificates for LERC Control to use, you need to complete your LERC Control configuration. By default, LERC Control checks the following locations for configuration files:

    /<python-lib-where-lerc_control-installed>/etc/lerc.ini
    /etc/lerc_control/lerc.ini
    /opt/lerc/lerc_control/etc/lerc.ini
    ~/<current-user>/.lerc_control/lerc.ini

Configuration items found in later config files take presendence over earlier ones. This allows for differernt users to have different settings, such as user specific validation certificates, and for default values to be overriden.

The following configuration items are required:

    [default]
    server=<url or hostname of LERC server>
    ignore_system_proxy=<True OR False>
    client_cert=<path to client certificate>
    client_key=<path to client certificate key>
    server_ca_cert=<path to the certificate authority cert that signed the LERC server cert>
    client_working_dir=<the default directory LERCs should work out of, something like 'C:\Program Files (x86)\Integral Defense\'>
    client_installer=<path to lercSetup.msi>
    lerc_install_cmd=<default client install command, something like 'msiexec /quiet /qn /l lerc_install.log /i lercSetup.msi company=0 reconnectdelay=15 chunksize=2048 serverurls="https://your-lerc-server/"'>
    production_lerc_version=<this should always reflect the current version string of the LERC you have in production, ex: 1.0.0.0>


### Default Config Items

The following are default values that can be overriden:

    [default]
    # script used to upgrade clients
    upgrade_bat=tools/upgrade.bat
    upgrade_cmd=upgrade.bat {} 15 2048 "https://{}/"
    # containment script used to perform safe containments
    containment_bat=tools/safe_contain.bat
    contain_cmd=safe_contain.bat {}

    [default_collect]
    # Browsing history
    browser_history_exe_path=tools/BrowsingHistoryView.exe    
    browserHistoryView_cmd=BrowsingHistoryView.exe /sort 2 /HistorySource 1 /VisitTimeFilterType 1 /scomma browserhistory.csv
    # see what processes have a handle on a specific file/directory, or '-a' to get handles for all running processs
    handles_file_cmd=handle.exe /accepteula "{}"
    # 7za for compressing files and directories by collect.py
    7za_path=tools/7za.exe
    7za_dir_cmd=7za.exe a -r {}.7z "{}" 

    [scripts]
    collect_browsing_history=scripts/collect_browsing_history.ini
    collect_wmi_data=scripts/collect_wmi_data.ini


## Documentation

Documentation is still a work in progress but you can find it here [http://lerc.readthedocs.io/](http://lerc.readthedocs.io/)
