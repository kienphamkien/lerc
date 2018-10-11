
import os
import sys
import time
import json
import atexit
import logging
import requests
from datetime import datetime
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
            try:
                r = requests.post(self.server+'/command', cert=self.cert, params=arguments)
                if r.status_code != requests.codes.ok:
                    self.logger.error(r.text)
                    return False
                self.logger.debug("Session destroyed.")
                return True
            except:
                return False
    
    def attach_host(self, host):
        if not host:
            return None
        if self.host and self.host != host:
            self._detach_host(self.server, self.host)
        self.host = host
        self.logger.debug("attaching to host '{}'..".format(host))

    def __init__(self, profile='default', server=None, host=None, cid=None, chunk_size=4096):
        config = ConfigParser()
        config_paths = []
        config_paths.append(os.path.join(os.getcwd(),'.config','session.ini'))
        config_paths.append('/opt/lerc_control/.config/session.ini')
        config_paths.append('/opt/lerc/lerc_control/.config/session.ini')
        for cp in config_paths:
            try:
                if os.path.exists(cp):
                    config.read(cp)
                    self.logger.debug("Reading config file at {}.".format(cp))
                    break
            except:
                pass
        else:
            raise Exception("No configuration file defined along search paths: {}".format(config_paths))
        if not config.has_section(profile):
            raise Exception("No section named '{}' in configuration file".format(profile))

        if server:
            self.server = server
        else:
            self.server = config[profile]['server']
        if not self.server.startswith('https://'):
            self.server = 'https://' + self.server
        if self.server[-1] == '/':
            self.server = self.server[:-1]
        if 'server_ca_cert' in config[profile]:
            self.logger.debug("setting 'REQUESTS_CA_BUNDLE' environment variable for HTTPS verification")
            os.environ['REQUESTS_CA_BUNDLE'] = config[profile]['server_ca_cert']
        self.client_cert = config[profile]['client_cert']
        self.client_key = config[profile]['client_key']
        self.cert = (self.client_cert, self.client_key)
        self.attach_host(host)
        self.command = None
        self.cid = cid
        self.error = None
        self.contained = False
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
                if 'error' not in result:
                    raise Exception("Unexpected result: {}".format(result))
                self.error = result['error']
                self.logger.error(self.error)
                return False

    def Run(self, shell_command):
        # execute a shell command on the host
        command = { "operation":"run", "command": shell_command }
        return self._issue_command(command)

    def Download(self, server_file_path, client_file_path=None, analyst_file_path=None):
        # Send file to endpoint - resume capable
        ## server_file_path - The server file to send to the client
        ## client_file_path - where the client should write the file, defaults to it's cwd
        ## analyst_file_path - path to the original file the analyst passed in - allows resume
        command = { "operation":"download", "server_file_path":server_file_path,
                    "client_file_path":client_file_path, "analyst_file_path":analyst_file_path}
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
            if 'message' in r: # server error
                self.logger.error("{} : {}".format(r['message'], r['error']))
            else: # error from client shouldn't be logged as errors here
                #self.logger.error("{}".format(r['error']))
                self.command = r
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

        if self.command['operation'] == 'DOWNLOAD' or self.command['operation'] == 'QUIT':
            self.logger.info("No results to get for '{}' operations".format(self.command['operation']))
            return self.command
        elif self.command['filesize'] == 0:
            self.logger.info("Command complete. No output to collect.")
            return self.command

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
                        f.write(r.raw.read(self.chunk_size))
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
            return self.command
        else:
            self.logger.info("Data stream closed prematurely. Have {}/{} bytes. Trying to resume..".
                              format(filesize, self.command['filesize']))
            self.get_results()
        return None

    def check_host(self, host=None):
        if host:
            self.attach_host(host)
        r = requests.get(self.server+'/command', params={'host': self.host}, cert=self.cert).json()
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
        if not os.path.exists(file_path):
            self.error = "{} does not exists. Aborting.".format(file_path)
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
                if not command['analyst_file_path']:
                    self.error = "Can't resume upload to server, analyst_file_path is not defined"
                    self.logger.error(self.error)
                    return False
                command = self.stream_file(command['analyst_file_path'], command['file_position'])
                if 'warn' in command:
                    self.logger.warn(command['warn'])
            else:
                self.logger.info("Command {} state: {}.".format(self.cid, command['status']))
                return command

    def contain(self):
        # isolate a host with the windows firewall
        # everything will be blocked but lerc's access outbound
        """
        netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
        netsh advfirewall firewall add rule name="LERC" dir=out action=allow program="C:\Program Files (x86)\Integral Defense\Live Endpoint Response Client\lerc.exe" enable=yes
        netsh advfirewall set allprofiles state on
        netsh advfirewall show allprofiles
        """

        # TODO: Drop a bat file to undo these changes and call it at the very end of the commands below -
        # at the beggining of the bat file, pause for 60 seconds. See next TODO comment->

        if self.contained:
            return self.contained

        self.logger.info("containing host..")
        # TODO: drop the bat file that will pause for 60 seconds and then undo all firewall changes we make
        self.Run('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound && \
                netsh advfirewall firewall add rule name="LERC" dir=out action=allow program="C:\\Program Files (x86)\\Integral Defense\\Live Endpoint Response Client\\lerc.exe" enable=yes && \
                netsh advfirewall set allprofiles state on')
        # TODO: self.Run("kill the bat file that should still be paused on the client (and then delete it?)")
        # After the firewall changes are made, the host should check back in and get the command to kill the bat file
        # If the host can not check back in, then, the bat file will un-do the firewall changes
        # This should keep us from locking ourselves out of a client
        self.wait_for_command(self.check_command())
        self.logger.info("Host contained at: {}".format(datetime.now()))
        self.logger.info("Getting firewall status for due diligence..")
        self.Run('netsh advfirewall show allprofiles')
        self.wait_for_command(self.check_command())
        self.get_results(file_path = "{}_firewall_containment.txt".format(self.host))
        self.contained = True
        return self.contained

    def release_containment(self):

        self.Run("netsh advfirewall reset && netsh advfirewall show allprofiles")
        self.wait_for_command(self.check_command())
        self.logger.info("Host containment removed at: {}".format(datetime.now()))
        self.logger.info("Getting firewall status for due diligence..")
        self.get_results(file_path = "{}_firewall_reset.txt".format(self.host))
        self.contained = False
        return self.contained
