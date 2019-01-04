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


## Documentation

Documentation is still a work in progress but you can find it here [http://lerc.readthedocs.io/](http://lerc.readthedocs.io/)
