Control API
===========

The control API can be used to issue commands to clients, download command results, check the status of commands or clients, isolate clients via the windows firewall, and more.

Setup
-----

LERC API
--------

.. autoclass:: lerc_control.lerc_api.lerc_session
    :members:

LERC User Interface
-------------------

The ``lerc_ui.py`` script can be used to perform several automated functions. Below is a description of the commands you can run with it:

    :Host Name: The host name of the client you want to work with is *Required*. If you only supply the hostname, the current default behavior is for the server to return the entire command queue for that host.

::

    $ lerc_ui.py -h
                      hostname {run,upload,download,quit,check,resume,get,contain}
                      ...

    User interface to the LERC control server

    positional arguments:
      hostname              the host you'd like to work with
      {run,upload,download,quit,check,resume,get,contain}
        run                 Run a shell command on the host.
        upload              Upload a file from the client to the server
        download            Download a file from the server to the client
        quit                tell the client to uninstall itself
        check               check on a specific command id
        resume              resume a pending command id
        get                 get results for a command id
        contain             Contain an infected host

    optional arguments:
      -h, --help            show this help message and exit


Examples
--------

Killing a process and deleting dir
++++++++++++++++++++++++++++++++++

Below, using ``lerc_ui.py`` to tell the client on host "WIN1234" to run a shell command that will kill `360bdoctor.exe`, change director to the directory where the application is installed, delete the contents of that directory, and then print the directory contents. The result of this command should return an emptry directory.

::

    $ lerc_ui.py WIN1234 run 'taskkill /IM 360bdoctor.exe /F && cd "C:\Users\bond007\AppData\Roaming\360se6\Application\" && del /S /F /Q "C:\Users\bond007\AppData\Roaming\360se6\Application\*" && dir'
