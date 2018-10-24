.. Live Endpoint Response Client documentation master file, created by
   sphinx-quickstart on Thu Oct 11 12:18:47 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Live Endpoint Response Client
=============================

The Live Endpoint Resposne Client (LERC) provides a service for resumable file transfer from client to server to analyst/user. Additionally, LERC acts as a Remote Access Solution with the following commands:


Major Features
--------------

+ Fast data transfer via chuncked streaming
+ Bi-directional file transfers automatically resume after broken connections
+ Run shell commands on clients and stream back results
+ Installed as a service with a MSI installer
+ Capability to sign the MSI and EXE you build
+ Client can be set to trust a custom server signing cert
+ All clients are verified by the server by a certificate you specify
+ Control API to interact with the server and control the clients
+ Clients will uninstall and delete themselves when issued a "quit" command
+ Server will only accept control commands from a verified certificate you provide

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   protocol
   build-install
   control-api

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
