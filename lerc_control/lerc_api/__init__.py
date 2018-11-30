
import os
import sys
import time
import json
import atexit
import pprint
import logging
import requests
from hashlib import md5
from datetime import datetime
from contextlib import closing
from configparser import ConfigParser

# Get the working lerc_control directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config(profile='default', required_keys=[]):
    """Load lerc configuration. Configuration files are looked for in the following locations::
        /etc/lerc_control/lerc.ini
        /opt/lerc/lerc_control/etc/lerc.ini
        ~/<current-user>/lerc_control/lerc.ini
        /<python-lib-where-lerc_control-installed>/etc/lerc.ini

    Configuration items found in later config files take presendence over earlier ones.

    :param str profile: (optional) Specifiy a group or company to work with.
    """
    logger = logging.getLogger(__name__+".load_config")
    config = ConfigParser()
    config_paths = []
    # global
    config_paths.append('/etc/lerc_control/lerc.ini')
    # legacy
    config_paths.append('/opt/lerc/lerc_control/etc/lerc.ini')
    # user specific
    config_paths.append(os.path.join(os.path.expanduser("~"),'.lerc_control','lerc.ini'))
    # local & defaults
    config_paths.append(os.path.join(BASE_DIR, 'etc', 'lerc.ini'))
    finds = []
    for cp in config_paths:
        if os.path.exists(cp):
            logger.debug("Found config file at {}.".format(cp))
            finds.append(cp)
    if not finds:
        logger.critical("Didn't find any config files defined at these paths: {}".format(config_paths))
        raise Exception("MissingLercConfig", "Config paths : {}".format(config_paths))

    config.read(finds)
    try:
        config[profile]
    except KeyError:
        logger.critical("No section named '{}' in configuration files : {}".format(profile, config_paths))
        raise

    if isinstance(required_keys, list) and required_keys:
        for key in required_keys:
            missing = False
            if not config.has_option(profile, key):
                for section in config.sections():
                    if not config.has_option(section, key):
                        missing = True
            if missing:
                logger.error("Missing required config item: {}".format(key))

    return config


class lerc_session():
    """Represents a Live Endpoint Response Client and Server control session.
    This class is for interacting and managing the LERC clients and server.

    Optional arguments:

    :profile: Specifiy a group or company to work with. These are defined in the lerc.ini config file.
    :server: The name the LERC control server to work with. Default is read from the lerc.ini config file.
    :host: A lerc client you want to auto-attach to by hostname.
    :cid: An existing command id you want to work with.
    :chunk_size: The chunk size to use when streaming files between a lerc_session and the LERC server

    """
    host = None
    server = None
    command = None
    logger = logging.getLogger(__name__+".lerc_session")

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
        """ Attach to a LERC client by hostname. If a host is already attached to this lerc_session, it will first be detached.
        """
        if not host:
            return None
        if self.host and self.host != host:
            self._detach_host()
        self.host = host
        self.logger.debug("attaching to host '{}'..".format(host))

    def __init__(self, profile='default', server=None, host=None, chunk_size=4096):
        self.config = load_config(profile)
        self.profile = profile
        if server:
            self.server = server
        else:
            self.server = self.config[profile]['server']
        if not self.server.startswith('https://'):
            self.server = 'https://' + self.server
        if self.server[-1] == '/':
            self.server = self.server[:-1]
        if 'server_ca_cert' in self.config[profile]:
            self.logger.debug("setting 'REQUESTS_CA_BUNDLE' environment variable for HTTPS verification")
            os.environ['REQUESTS_CA_BUNDLE'] = self.config[profile]['server_ca_cert']
        self.client_cert = self.config[profile]['client_cert']
        self.client_key = self.config[profile]['client_key']
        self.cert = (self.client_cert, self.client_key)
        if 'ignore_system_proxy' in self.config[profile]:
            if self.config[profile].getboolean('ignore_system_proxy'):
                # route direct
                if 'https_proxy' in os.environ:
                    del os.environ['https_proxy']
        self.attach_host(host)
        self.command = None
        self.error = None
        self.contained = False
        self.chunk_size = chunk_size
        atexit.register(self._detach_host)

    @property
    def get_config(self):
        return self.config

    @property
    def get_profile(self):
        return self.profile

    @property
    def hostname(self):
        return self.host

    def _issue_command(self, command):
        # check the host, make the post
        if not self.host:
            self.logger.error("No host has been specified.")
            return False
        arguments = {'host': self.host}
        headers={"content-type": "application/json"}
        r = requests.post(self.server+'/command', cert=self.cert, headers=headers,
                                        params=arguments, data=json.dumps(command))
        if r.status_code != requests.codes.ok:
            self.error = { 'status_code': r.status_code, 'message': "ERROR : {}".format(r.text) }
            self.logger.error(self.error['message'])
            return False
        else: # record the command
            result = r.json()
            if 'command_id' in result:
                self.logger.info("{} (CID: {})".format(result['message'], result['command_id']))
                self.command = result
                return result
            else:
                if 'error' not in result:
                    raise Exception("Unexpected result: {}".format(result))
                self.error = result['error']
                self.logger.error(self.error)
                return False

    def Run(self, shell_command, async=False):
        """Execute a shell command on the host.

        :param str shell_command: The command to run on the host
        :param bool async: (optional) ``False``: LERC client will stream any results and  wait until for completion. ``True``: Execute the command and return immediately.
        """
        command = { "operation":"run", "command": shell_command, "async": async }
        self._issue_command(command)
        return self.check_command()

    def Download(self, server_file_path, client_file_path=None, analyst_file_path=None):
        """Instruct a client to download a file. The file will be streamed to the server if the server doesn't have it yet. The streamed to the client.

        :param str server_file_path: The path to the file that you want the client to download. If the supplied argument is the path to the file on the system this function is called, an attempt will be made to complete the analyst_file_path automatically.
        :param str client_file_path: (optional) where the client should write the file, defaults server config default directory + the file name taken off of the server_file_path.
        :param str analyst_file_path: (optional) path to the original file the analyst - This allows an analyst to resume a transfer between a lerc_session and the server. Neccessary for streaming the file to the server, if the server does not already have it
        """
        if analyst_file_path is None:
            analyst_file_path = server_file_path

        if '/' in server_file_path:
            server_file_path = server_file_path[server_file_path.rfind('/')+1:]

        command = { "operation":"download", "server_file_path":server_file_path,
                    "client_file_path":client_file_path, "analyst_file_path":analyst_file_path}

        self._issue_command(command)
        return self.stream_file(analyst_file_path)

    def Upload(self, path):
        """Upload a file from client to server. The file will be streamed to the server and then streamed to the lerc_session.

        :param str path: The path to the file, on the endpoint
        """
        command = { "operation":"upload", "client_file_path":path }
        self._issue_command(command)
        return self.check_command()

    def Quit(self):
        """The Quit command tells the LERC client to uninstall itself from the endpoint.
        """
        command = { "operation":"quit" }
        self._issue_command(command)
        return self.check_command()

    def list_directory(self, dir_path):
        """List the given directory, read the results into a list and return the list.
        """
        command = self.Run('cd "{}" && dir'.format(dir_path))
        command = self.wait_for_command(command)
        results = self.get_results(command['command_id'], return_content=True)
        return results.decode('utf-8').splitlines()

    def check_command(self, cid=None):
        """Check on a specific command by id. If None is give, the command_id in any command associated to this lerc_session will be used. Else, return False.

        :param int cid: (optional) The Id of a command you want to get the status of.
        :return: Dictionary representation of a command
        """
        if not cid:
            if not self.command:
                self.logger.error("No command has been attached to this session")
                return False
            cid = self.command['command_id']

        arguments = {'cid':cid}
        if self.host:
            arguments['host'] = self.host
        self.logger.debug("Trying to get command {}".format(cid))
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

    def get_results(self, cid=None, file_path=None, chunk_size=None, print_run=True, return_content=False, position=0):
        """Get any results available for a command. If cid is None, any cid currently assigned to the lerc_session will be used.

        :param int cid: (optional) The Id of a command to work with.
        :param str file_path: (optional) The path to write the results. default: <hostname>_<cid>_filename to current dir.
        :param int chunk_size: (optional) Specify the size of the chunks (bytes) to stream with the server
        :param boolean print_run: (optionl default:True) If True, print Run command results to console
        :param boolean return_content: (content) Do not write the results to a file, return the results as a byte string
        :param int position: (optional) For manually specifing byte position
        :return: If return_content==True, the raw content will be returned as a byte string, else the command is return on success. 
        """
        if not cid:
            if not self.command:
                self.logger.error("No command has been attached to this session")
                return False
            cid = self.command['command_id']

        # make sure the command is up-to-date
        self.check_command(cid)

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
        if os.path.exists(file_path):
            statinfo = os.stat(file_path)
            position = statinfo.st_size
            self.logger.info("Already have {} out of {} bytes. Resuming download from server.."
                             .format(position, self.command['filesize']))
        else:
            self.logger.debug("getting results for {}".format(cid))

        arguments = {'position': position, 'cid': cid}
        headers = {"Accept-Encoding": '0'}

        if self.command['status'] != 'COMPLETE' or self.command['status'] != 'STARTED':
            self.logger.warn("Any results for commands in state={} can not be reliably streamed.".format(self.command['status']))
            return requests.get(self.server+'/command/download', cert=self.cert, params=arguments).json()

        raw_bytes = None
        total_chunks, remaining_bytes = divmod(self.command['filesize'] - position, self.chunk_size)
        with closing(requests.get(self.server+'/command/download', cert=self.cert, params=arguments, headers=headers, stream=True)) as r:
            try:
                r.raw.decode_content = True
                # are we returning the raw bytes?
                if return_content:
                    raw_bytes = b''
                    for i in range(total_chunks):
                        raw_bytes += r.raw.read(self.chunk_size)
                    raw_bytes += r.raw.read(remaining_bytes)
                    return raw_bytes
                else:
                    with open(file_path, 'ba') as f:
                        for i in range(total_chunks):
                            if self.command['operation'] == 'RUN' and print_run:
                                print(r.raw.read(self.chunk_size).decode('utf-8'))
                            f.write(r.raw.read(self.chunk_size))
                        final_chunk = r.raw.read(remaining_bytes)
                        if self.command['operation'] == 'RUN' and print_run:
                            print(final_chunk.decode('utf-8'))
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
        """Get the status of a client by hostname. Will attach the lerc_session to the hostname if the client exists.

        :param str host: (optional) The hostname of a lerc client.
        :return: A lerc client summary or False
        :rtype: dict representation of client or False
        """
        if not host and not self.host:
            self.logger.error("No host specified.")
            return False
        if not host:
            host = self.host
        r = requests.get(self.server+'/command', params={'host': host}, cert=self.cert).json()
        if 'client' in r:
            self.attach_host(host)
            return r['client']
        else:
            self.logger.warn("{}".format(r))
            return False

    def get_hosts(self):
        """Yeild dictionary representations of lerc clients.
        """
        host_id = 0
        r = requests.get(self.server+'/command', params={'hid': host_id}, cert=self.cert).json()
        # there is no host by id 0, but when you query the server for a hid that doesn't exsit,
        # the response will be an error, that also contains a list of the valid host ids
        if 'host_ids' not in r:
            self.logger.error('Unexpected answer from server: result="{}"'.format(r))
            raise Exception('Unexpected answer from server', 'result="{}"'.format(r))
        hids = r['host_ids']
        for host_id in hids:
            r = requests.get(self.server+'/command', params={'hid': host_id}, cert=self.cert).json()
            if 'error' in r:
                self.logger.error("{}".format(r['error']))
            yield r

    def get_command_queue(self, host=None):
        """Get the entire command queue for a lerc client by hostname.

        :param str host: (optional) The hostname of a lerc client.
        :return: A list of commands for a client, each list entry is a dictionary representation of a command
        """
        if host:
            self.attach_host(host)
        if not self.host:
            self.logger.error("No host specified.")
            return False
        r = requests.get(self.server+'/command', params={'host': self.host}, cert=self.cert).json()
        if 'commands' in r:
            return r['commands']
        else:
            self.logger.error("{}".format(r))
            return r

    def stream_file(self, file_path, position=0):
        # file_path - file to send
        # position - position in file to send from (resume capable)
        if not self.host:
            self.error = "No host has been specified host."
            self.logger.error(self.error)
            return False

        if not self.command:
            self.error = "No command associated with this session"
            self.logger.error(self.error)
            return False
        cid = self.command['command_id']

        if not os.path.exists(file_path):
            self.error = "{} does not exists. Aborting.".format(file_path)
            self.logger.error(self.error)
            return False

        # get md5 of file
        md5_hasher = md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hasher.update(chunk)
        file_md5 = md5_hasher.hexdigest().lower()

        statinfo = os.stat(file_path)        
        arguments = {'host': self.host, 'cid': cid, 'filesize': statinfo.st_size, 'md5': file_md5}
        def gen():
            with open(file_path, 'rb') as f:
                f.seek(position)
                data = f.read(4096)
                while data:
                    yield data
                    data = f.read(4096)
                #break
        r = requests.post(self.server+'/command/upload', cert=self.cert, params=arguments, data=gen()).json()
        if 'error' in r:
            self.logger.error("{}".format(r['error']))
            return r
        self.command = r
        return self.command

    def wait_for_command(self, command):
        """Wait for a command to complete by continously querying for its status to change to 'COMPLETE' with the server.

        :param str command: A dictionary representation of a lerc command.
        :return: Any results returned by a Run command or a file that was collected off of a client 
        """
        while command:
            cid = command['command_id']
            status = command['status']
            if status == 'PENDING': # we wait
                self.logger.info("Command {} PENDING. Checking again in 10 seconds..".format(cid))
                time.sleep(10)
                command = self.check_command(cid=cid)
            elif status == 'PREPARING': # the command needs something from us (file)
                if command['operation'] != "DOWNLOAD":
                    self.error = "Command {} is PREPARING but we don't know what for.".format(cid)
                    self.logger.error(self.error)
                    return False
                self.logger.info("Command {} PREPARING. Streaming file to server..".format(cid))
                # function to stream file to server
                if not command['analyst_file_path']:
                    self.error = "Can't resume upload to server, analyst_file_path is not defined"
                    self.logger.error(self.error)
                    return False
                command = self.stream_file(command['analyst_file_path'], command['file_position'])
                if 'warn' in command:
                    self.logger.warn(command['warn'])
            elif status == 'STARTED':
                self.logger.info("Command {} STARTED. Checking again in 10 seconds..".format(cid))
                time.sleep(10)
                command = self.check_command(cid=cid)
            else:
                self.logger.info("Command {} state: {}.".format(cid, command['status']))
                return command

    def contain(self):
        """Use the windows firewall to isolate a host. Everything will be blocked but lerc's access outbound. You must attach to a host before using contain.
        This is implemented by dropping a bat file (a default is included in the lerc_control/tools dir) that will isolate a host with the windows firewall and only allow the lerc.exe client access through the firewall. The bat file will pause for ~60 seconds without prompting the user. Lerc is issued a run command to kill the bat file. If Lerc is able to fetch this run command from the control server, the bat file will be killed before the 60 seconds are up. If not, the bat file will undo all firewall changes.

        :return: True on success
        """

        if self.contained:
            return self.contained

        self.logger.info("containing host..")
        status = self.check_host()
        if not status:
            self.logger.error("Not attached to a host")
            return False
        safe_contain_bat_path = self.config[self.profile]['containment_bat']
        contain_cmd = self.config[self.profile]['contain_cmd']

        self.Download(safe_contain_bat_path)
        containment_command = self.Run(contain_cmd.format(int(status['sleep_cycle'])+5), async=True)

        # Dummy command to give the containment command enough time to execute before lerc kills it with wmic
        self.Run("dir")
 
        bat_name = safe_contain_bat_path[safe_contain_bat_path.rfind('/')+1:]
        kill_command = self.Run('wmic process where "CommandLine Like \'%{}%\'" Call Terminate'.format(bat_name))

        # for spot checking
        check_command = self.Run('netsh advfirewall show allprofiles')

        containment_command = self.wait_for_command(containment_command)
        self.logger.info(pprint.pformat(containment_command))
        self.logger.info("Host contained at: {}".format(datetime.now()))
        
        self.logger.info("Command {} should return before {} seconds have passed.".format(kill_command['command_id'], status['sleep_cycle']))
        kill_command = self.wait_for_command(kill_command)
        self.logger.info(pprint.pformat(kill_command))

        self.logger.info("Getting firewall status for due diligence..")
        check_command = self.wait_for_command(check_command)
        self.get_results(file_path = "{}_{}_firewall_status.txt".format(self.host, check_command['command_id']), print_run=False)

        self.contained = True
        return self.contained

    def release_containment(self):
        """Release containment on client.

        :return: True on success.
        """
        if self.host is None:
            self.logger.error("Not attached to a host")
            return False
        self.Run("netsh advfirewall reset && netsh advfirewall show allprofiles")
        self.wait_for_command(self.check_command())
        self.logger.info("Host containment removed at: {}".format(datetime.now()))
        self.logger.info("Getting firewall status for due diligence..")
        cid = self.command['command_id']
        self.get_results(file_path = "{}_{}_firewall_reset.txt".format(self.host, cid), print_run=False)
        self.contained = False
        return not self.contained
