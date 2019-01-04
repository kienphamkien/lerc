Control API
===========

The control API can be used to issue commands to clients, download command results, check the status of commands or clients, isolate clients via the windows firewall, and more.

Setup
-----

LERC API
--------

.. automodule:: lerc_control.lerc_api
    :members:

.. automodule:: lerc_control
    :members:

.. autoclass:: lerc_control.lerc_api.lerc_session
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
--------

Killing a process and deleting dir
++++++++++++++++++++++++++++++++++

Below, using ``lerc_ui.py`` to tell the client on host "WIN1234" to run a shell command that will kill `360bdoctor.exe`, change director to the directory where the application is installed, delete the contents of that directory, and then print the directory contents. The result of this command should return an emptry directory.

::

    $ lerc_ui.py run WIN1234 'taskkill /IM 360bdoctor.exe /F && cd "C:\Users\bond007\AppData\Roaming\360se6\Application\" && del /S /F /Q "C:\Users\bond007\AppData\Roaming\360se6\Application\*" && dir'
