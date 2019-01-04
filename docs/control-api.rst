LERC Control
============

The LERC control library is a python wrapper around the server API that provides several ulitlites and functions for controling and issuing commands to clients. A ``lerc_ui`` script is included if installed with pip3 that provides a powerful command line user interface to this library.

Setup
-----

Use pip3 to install lerc-control::

    pip3 install lerc-control

Note that you will need to have a working LERC Server and workign clients to use LERC Control.

LERC API Library
----------------

The LERC API module is the foundation for interacting with clients. The LERC Control library is built around it.

.. automodule:: lerc_control.lerc_api
    :members:

Control Library
---------------

The LERC Control library used the LERC API to perform live response funtions, such as performing scripted routines, as well as more complex collections and remediations.

Structure::

    /lerc_control
      __init__.py
      scripted.py
      collect.py
      remediate.py
      helpers.py

.. automodule:: lerc_control
    :members:

Scripted
~~~~~~~~

The scripted module should only contain classes and functions for running or related to scripted routines.

.. automodule:: lerc_control.scripted
    :members:

Collect
~~~~~~~

All Live Response collection related classes and function belong in the collect module.

.. automodule:: lerc_control.collect
    :members:

Remediate
~~~~~~~~~

All Live Response remediation related classes and functions belong in the remediate module.

.. automodule:: lerc_control.remediate
    :members:

Helpers
~~~~~~~

Global helper and general functions and classes belong in this module.

.. automodule:: lerc_control.helpers
    :members:


LERC User Interface
-------------------

The ``lerc_ui`` or ``lerc_ui.py`` script can be used to perform several automated functions. Below is a description of the commands you can run with it:

::

    $ lerc_ui -h
    usage: lerc_ui.py [-h] [-e ENVIRONMENT] [-d] [-c CHECK] [-r RESUME] [-g GET]
                      {query,run,upload,download,quit,collect,contain,script} ...

    User interface to the LERC control server

    positional arguments:
      {query,run,upload,download,quit,collect,contain,script}
        query               Query the LERC Server
        run                 Run a shell command on the host.
        upload              Upload a file from the client to the server
        download            Download a file from the server to the client
        quit                tell the client to uninstall itself
        collect             Default (no arguments): perform a full lr.exe
                            collection
        contain             Contain an infected host
        script              run a scripted routine on this lerc.

    optional arguments:
      -h, --help            show this help message and exit
      -e ENVIRONMENT, --environment ENVIRONMENT
                            specify an environment to work with. Default='default'
      -d, --debug           set logging to DEBUG
      -c CHECK, --check CHECK
                            check on a specific command id
      -r RESUME, --resume RESUME
                            resume a pending command id
      -g GET, --get GET     get results for a command id


Examples
~~~~~~~~

Killing a process and deleting dir
++++++++++++++++++++++++++++++++++

Below, using ``lerc_ui.py`` to tell the client on host "WIN1234" to run a shell command that will kill `360bdoctor.exe`, change director to the directory where the application is installed, delete the contents of that directory, and then print the directory contents. The result of this command should return an emptry directory.

::

    $ lerc_ui.py run WIN1234 'taskkill /IM 360bdoctor.exe /F && cd "C:\Users\bond007\AppData\Roaming\360se6\Application\" && del /S /F /Q "C:\Users\bond007\AppData\Roaming\360se6\Application\*" && dir'


Querying
++++++++

The server supports a very basic query language. Query fields are only ANDed together and negation is supported by placing a '-', '!', or 'NOT ' in directly in front of the field to be negated. Note, the ``-rc`` option will explicitly return commands is set, else commands are only returned if a 'cmd_*' field is specified in the query.

Available Fields:

Field           Description                                                                     
==============  ================================================================================
cmd_status      The status of a command: pending,preparing,complete,error,unknown,started       
cmd_id          The ID of a specific command                                                    
company         A company/group name                                                            
client_status   A LERC status: busy,online,offline,unknown,uninstalled                          
version         The LERC version string                                                         
hostname        The hostname of a client                                                        
company_id      Specify a company/group ID                                                      
client_id       Specify a LERC by ID                                                            
operation       A Command operation type: upload,run,download,quit


Query for a specific host::

    $ lerc_ui.py query 'hostname:w7gotchapc'

    Client Results:

    ID     Hostname              Status       Version   Sleep Cycle  Install Date          Last Activity         Company ID
    =====  ====================  ===========  ========  ===========  ====================  ====================  ==========
    14     W7GOTCHAPC            OFFLINE      1.0.0.0   60           2018-12-12 14:19:18   2018-12-14 14:40:56   0         
    Total Client Results:1


Not Run commands that have errored for this host, which is not online::

    $ lerc_ui.py query 'hostname:w7gotchapc -client_status:online -operation:run cmd_status:error'

    Client Results:

    ID     Hostname              Status       Version   Sleep Cycle  Install Date          Last Activity         Company ID
    =====  ====================  ===========  ========  ===========  ====================  ====================  ==========
    14     W7GOTCHAPC            OFFLINE      1.0.0.0   60           2018-12-12 14:19:18   2018-12-14 14:40:56   0         
    Total Client Results:1


    Command Results:

    ID         Client ID  Hostname              Operation    Status   
    =========  =========  ====================  ===========  =========
    320        14         w7gotchapc            DOWNLOAD     ERROR    
    322        14         w7gotchapc            DOWNLOAD     ERROR    
    377        14         w7gotchapc            UPLOAD       ERROR    
    609        14         w7gotchapc            UPLOAD       ERROR    
    696        14         w7gotchapc            UPLOAD       ERROR    
    807        14         w7gotchapc            UPLOAD       ERROR    
    983        14         w7gotchapc            UPLOAD       ERROR    
    986        14         w7gotchapc            UPLOAD       ERROR    
    997        14         w7gotchapc            UPLOAD       ERROR    
    1001       14         w7gotchapc            UPLOAD       ERROR


Check on a Command
++++++++++++++++++

::

    $ lerc_ui.py -c 1002

    ----------------------------
    Command ID: 1002
    Client ID: 14
    Hostname: w7gotchapc
    Operation: RUN
      |-> Command: cd "C:\Program Files (x86)\Integral Defense\" && Del "C:\Program Files (x86)\Integral Defense\w7gotchapc_dirOfInterest.zip"
      |-> Async: False
    Status: COMPLETE
    Client Filepath: None
    Server Filepath: data/W7GOTCHAPC_RUN_1002
    Analyst Filepath: None
    File Position: 0
    File Size: 84


