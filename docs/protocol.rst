The LERC Protocol
=================

Each endpoint fetches the current command from the server by sending a GET request to /fetch. The machine name of the endpoint is passed in the query string variable "host" and an integer is passed representing the company/organization/group the host belogs to in the variable "company". Below is an example fetch request uri.

``https://your-server/fetch?host=WIN1234&company=0``

The server then returns a JSON string containing the commands for the host to execute. The supported commands are:

+ Run
+ Sleep
+ Download
+ Upload
+ Quit

LERC Commands
=============

Sleep
-----

The sleep command tells the endpoint to do nothing for some number of seconds. Below is an example sleep command which tells the endpoint to do nothing for 30 minutes.

``{ "operation":"sleep", "seconds":1800 }``

Parameters
++++++++++

    :operation: The operation to perform.
    :seconds: Number of seconds to wait before contacting the server again.

Run
---

The run command tells the endpoint to execute a shell command. Below is an example run command which tells the endpoint to execute "echo hello world"

``{ "operation":"run", "id":"1234", "command":"echo hello world" }``

Parameters
++++++++++

    :operation: The operation to perform.
    :command: The shell command to execute.

Result
++++++

The endpoint will begin executing the command and streaming the output back to the server in a POST request to /pipe. The machine name and command id are sent via the query string variables "host" and "id".

``https://your-server/pipe?host=WIN1234&id=1234``

Download
--------

The download command is for sending files to endpoints.

``{ "operation":"download", "id":"1234", "path":"c:\\HelloWorld.txt" }``

Parameters
++++++++++

    :operation: Ther operation to perform
    :id: The command id
    :path: The path on the endpoint to write the data

Result
++++++

The endpoint sends a GET request to /download. The query string will contain the variables "host", "id" and "position". The host variable contains the machine name. The id variable is the command id. The position variable tells the server how much of the file is already downloaded. The server should then start streaming data to the client.

``https://your-server/download?host=WIN1234&id=1234&position=0``

Upload
------

The upload command is for sending files from endpoints to the server.

``{ "operation":"upload", "id":"1234", "path":"c:\\HelloWorld.txt", "position":0 }``

Parameters
++++++++++

    :operation: The operation to perform
    :id: The command id
    :path: The path on the endpoint to read the data from
    :position: The position in the file to start reading data. This is used to resume upload commands

Result
++++++

The endpoint sends a POST request to /upload and begins streaming data to the server. The query string contains the host, id and size variables. The host variable is the machine name. The id variable is the command id. The size variable is the size of the target file.

``https://your-server/upload?host=WIN1234&id=1234``

Quit
----

The Quit command tells the client to uninstall itself from the endpoint.

``{ "operation":"quit" }``


Errors
------

If LERC encounters an unexpected error while executing a command it will send a POST request to /error. The query string will contain the host and id variables. The host variable is the machine name and the id variable is the command id. The post data will contain the error message.

``https://your-server/error?host=WIN1234&id=1234``
