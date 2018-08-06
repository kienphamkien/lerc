
import os
import sys
import time
import json
import atexit
import logging
import requests
from contextlib import closing
from configparser import ConfigParser

#Live Endpoint Response Clients control session
# This class is for interacting and managing the lerc clients and server
class lerc_session():
    host = None
    server = None
    command = None
    cid = None
    logger = logging.getLogger(__name__)

    def _detach_host(self): #, server, host):
        # tell the server we're done with the host
        if self.host:
            arguments = {'host': self.host, 'detach': True}
            r = requests.post(self.server+'/command', cert=self.cert, params=arguments)
            if r.status_code != requests.codes.ok:
                self.logger.error(r.text)
                return False
            self.logger.debug("Detached from {}. Host's sleep cycle will be set back to default.".format(self.host))
            return True
    
    def attach_host(self, host):
        if not host:
            return None
        if self.host and self.host != host:
            self._detach_host(self.server, self.host)
        self.host = host
        self.logger.debug("attached to host '{}'".format(host))

    def __init__(self, profile='default', server=None, host=None, cid=None, chunk_size=4096):
        config = ConfigParser()
        local_configpath = os.path.join(os.getcwd(),'.config','session.ini')
        print(requests.__version__)
        configpath = '/opt/lerc_control/.config/session.ini'
        if local_configpath:
            try:
                config.read(local_configpath)
                self.logger.debug("found local configuration file. Reading '{}' profile.".format(profile))
            except Exception as e:
                pass
        else:
            try:
                config.read(configpath)
                self.logger.debug("Reading '{}' profile from default configuration file".format(profile))
            except Exception as e:
                self.logger.error("Could not find configuration file.")
                raise Exception("Could not find configuration file.")
        if not config.has_section(profile):
            self.logger.error("No section named '{}' in configuration file".format(profile))
            raise Exception("No section named '{}' in configuration file".format(profile))

        # this seems to only be neccessary for debian systems running in AWS 
        if 'REQUESTS_CA_BUNDLE' not in os.environ:
            self.logger.debug("setting 'REQUESTS_CA_BUNDLE' environment variable for HTTPS verification")
            os.environ['REQUESTS_CA_BUNDLE'] = '/usr/local/share/ca-certificates/integral-ca.pem'

        if server:
            self.server = server
        else:
            self.server = config.get(profile, 'server')
        if not self.server.startswith('https://'):
            self.server = 'https://' + self.server
        if self.server[-1] == '/':
            self.server = self.server[:-1]
        self.client_cert = config.get(profile, 'client_cert')
        self.client_key = config.get(profile, 'client_key')
        self.cert = (self.client_cert, self.client_key)
        self.attach_host(host)
        self.command = None
        self.cid = cid
        self.error = None
        self.chunk_size = chunk_size
        atexit.register(self._detach_host)

    def _issue_command(self, command):
        # check the host, make the post
        if not self.host:
            self.error = "No host has been specified."
            self.logger.error(self.error)
            return False
        arguments = {'host': self.host}
        headers={"content-type": "application/json"}
        r = requests.post(self.server+'/command', cert=self.cert, headers=headers,
                                        params=arguments, data=json.dumps(command))
        if r.status_code != requests.codes.ok:
            self.error = { 'status_code': r.status_code, 'message': "ERROR : {}".format(r.text) }
            self.logger.error(self.error['message'])
            return False
        else: # record the command id
            result = r.json()
            if 'command_id' in result:
                self.logger.info("{} (CID: {})".format(result['message'], result['command_id']))
                self.cid = result['command_id']
                return result
            else:
                self.logger.error(result)
                return False

    def Run(self, shell_command):
        # execute a shell command on the host
        command = { "operation":"run", "command": shell_command }
        return self._issue_command(command)

    def Download(self, server_file_path, client_file_path=None):
        # Send file to endpoint - resume capable
        ## server_file_path - The server file to send to the client
        ## client_file_path - where the client should write the file, defaults to it's cwd
        command = { "operation":"download", "server_file_path":server_file_path, "client_file_path":client_file_path }
        return self._issue_command(command) 

    def Upload(self, path):
        # upload file from endpoint to server
        ## path - The path on the endpoint to read the data from
        command = { "operation":"upload", "client_file_path":path }
        return self._issue_command(command)

    def Quit(self):
        # tells the endpoint to close the lerc executable and disable auto start.
        command = { "operation":"quit" }
        return self._issue_command(command)

    def check_command(self, cid=None):
        if self.cid is None:
            if  cid is None:
                self.error = "No command id to check"
                self.logger.error(self.error)
                return False
            else:
                self.cid = cid
        arguments = {'cid':self.cid}
        if self.host:
            arguments['host'] = self.host
        self.logger.debug("Trying to get command {}".format(self.cid))
        r = requests.get(self.server+'/command', cert=self.cert, params=arguments).json()
        if 'error' in r:
            logger.warn("Server returned error message: {}".format(r['error']))
            return r
        if 'hostname' in r and self.host is None:
            self.attach_host(r['hostname'])
        # save/update a copy of the current command
        self.command = r
        return self.command

    def get_results(self, cid=None, file_path=None, chunk_size=None):
        # get any results available for a command
        ## file_path - the path to write the results. default: write the server file name to current dir
        if cid and self.cid:
            if cid != self.cid:
                self.logger.warn("Updating self with current status of the command id passed")
                self.cid = cid
                self.check_command(cid)
        elif cid and not self.cid:
            self.cid = cid
            self.check_command(cid)
        if not self.cid:
            self.logger.error("No command has been attached to this session")
            return False

        if chunk_size:
            self.chunk_size = chunk_size

        if not file_path:
            file_path = self.command['server_file_path']
        file_path = file_path[file_path.rfind('/')+1:] if file_path.startswith('data/') else file_path

        # Do we already have some of the result file?
        position = 0
        if os.path.exists(file_path):
            statinfo = os.stat(file_path)
            position = statinfo.st_size
            self.logger.info("Already have {} out of {} bytes. Resuming download from server.."
                             .format(position, self.command['filesize']))
        else:
            self.logger.debug("getting results for {}".format(self.cid))
        arguments = {'position': position, 'cid': self.cid}
        headers = {"Accept-Encoding": '0'}
        total_chunks, remaining_bytes = divmod(self.command['filesize'] - position, self.chunk_size)
        with closing(requests.get(self.server+'/command/download', cert=self.cert, params=arguments, headers=headers, stream=True)) as r:
            try:
                r.raw.decode_content = True
                with open(file_path, 'ba') as f:
                    for i in range(total_chunks):
                        f.write(chunk)
                    final_chunk = r.raw.read(remaining_bytes)
                    f.write(final_chunk)
                    f.close()
            except Exception as e:
                self.logger.error(str(e))
                return False
        # Did we get the entire result file?
        filesize = os.stat(file_path).st_size
        if self.command['filesize'] == filesize:
            self.logger.info("Result file download complete. Wrote {}.".format(file_path))
            return True
        else:
            self.logger.info("Data stream closed prematurely. Have {}/{} bytes. Trying to resume..".
                              format(filesize, self.command['filesize']))
            self.get_results()
        return None

    def check_host(self, host=None):
        if host:
            self.attach_host(host)
        r = requests.get(self.server+'/command', params={'host': self.host}, cert=self.cert).json()
        if 'error' in r:
            self.logger.warn("Server returned error message: {}".format(r['error']))
        return r

    def get_command_queue(self, host=None):
        # return a hosts command queue
        r = self.check_host(host)
        if 'commands' in r:
            return r['commands']
        # returning a list of commands
        return r

    def stream_file(self, file_path, position=0):
        # file_path - file to send
        # position - position in file to send from (resume capable)
        if not self.host:
            self.error = "No host has been specified host."
            self.logger.error(self.error)
            return False
        if not self.cid:
            self.error = "No command id."
            self.logger.error(self.error)
            return False
        statinfo = os.stat(file_path)
        arguments = {'host': self.host, 'cid': self.cid, 'filesize': statinfo.st_size}
        def gen():
            with open(file_path, 'rb') as f:
                f.seek(position)
                data = f.read(4096)
                while data:
                    yield data
                    data = f.read(4096)
                #break
        self.command = requests.post(self.server+'/command/upload', cert=self.cert, params=arguments, data=gen()).json()
        return self.command

    def wait_for_command(self, command):
        # command - dict representation of a lerc command
        while command:
            status = command['status']
            if status == 'PENDING': # we wait
                self.logger.info("Command {} PENDING. Checking again in 10 seconds..".format(self.cid))
                time.sleep(10)
                command = self.check_command()
            elif status == 'PREPARING': # the command needs something from us (file)
                if command['operation'] != "DOWNLOAD":
                    self.error = "Command {} is PREPARING but we don't know what for.".format(self.cid)
                    self.logger.error(self.error)
                    return False
                self.logger.info("Command {} PREPARING. Streaming file to server..".format(self.cid))
                # function to stream file to server
                command = self.stream_file(args.file_path, command['file_position'])
                if 'warn' in command:
                    self.logger.warn(command['warn'])
            else:
                self.logger.info("Command {} state: {}.".format(self.cid, command['status']))
                return command
