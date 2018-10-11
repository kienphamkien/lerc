# Live Endpoint Response Client

The Live Endpoint Response Client (LERC) acts as a remote access solution but was originally developed to solve the problem of transferring large files over garbage internet connections and constant endpoint up/down scenarios. LERC is capable to resuming file transfers from client to server and server to client.


### Features

+ LERC is installed on windows hosts as a service.
+ MSI installer (lercSetup.msi)
+ Capable of accepting a list of control servers.
+ clients (and analysts) are verified via certificates


## Getting Started

You will need to do stuff.

## Project Breakdown

+ lerc_control - api interface to lerc_server with a basic ui script
+ lerc_server - the server
+ lerc_client - the client code (c#)

## Documentation

Documentation is still a work in progress but you can find it here [http://lerc.readthedocs.io/](http://lerc.readthedocs.io/)
