#!/usr/bin/python3

import os
import sys
import json
import logging
import pytz
import configparser
from hashlib import md5
from datetime import datetime
from flask_restful import Resource, Api
from flask import Flask, request, jsonify, stream_with_context, Response, make_response

# only used if we're runing the app natively
from werkzeug.serving import WSGIRequestHandler

import library.clientInstructions as ci
from library.database import db, operationTypes, cmdStatusTypes, clientStatusTypes, Commands, Clients, CompanyMapping

# TODO these should go in config files - also, convert to yaml config
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DATA_DIR = 'data/'
LOG_DIR = 'logs/'
ETC_DIR = 'etc/'
CLIENT_ERROR_DIR = LOG_DIR + 'client_errors/'
DIRECTORIES = [DATA_DIR, LOG_DIR, ETC_DIR, CLIENT_ERROR_DIR]
# make sure all the directories exists that need to exist
for path in [os.path.join(BASE_DIR, x) for x in DIRECTORIES]:
    if not os.path.isdir(path):
        try:
            os.mkdir(path)
        except Exception as e:
            sys.stderr.write("ERROR: cannot create directory {0}: {1}\n".format(
                path, str(e)))
            sys.exit(1)

config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, ETC_DIR, 'lerc_server.ini'))

# globals and config items
DEFAULT_CLIENT_DIR = config['lerc_server']['default_client_dir']
DEFAULT_SLEEP = int(config['lerc_server']['default_client_sleep'])
CHUNK_SIZE = int(config['lerc_server']['chunk_size'])
DB_server = config['lerc_server']['dbserver']
DB_user = config['lerc_server']['dbuser']
DB_userpass = config['lerc_server']['dbuserpass']
database_connect_string = "mysql+pymysql://{}:{}@{}/lerc".format(DB_user, DB_userpass, DB_server)

# To handle the edgecase between HTTP/1.1 and WSGI spec
UGLY_CHUNKSIZE = 1 # yep, 1 byte

# Declare app, api, and initilize db
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = database_connect_string
db.init_app(app)
api = Api(app)

@app.before_request
def handle_chunking():
    """
    Sets the "wsgi.input_terminated" environment flag, thus enabling
    Werkzeug to pass chunked requests as streams; this makes the API
    compliant with the HTTP/1.1 standard.  The server should set
    the flag, but this feature has not been implemented.
    """
    transfer_encoding = request.headers.get("Transfer-Encoding", None)
    if transfer_encoding == "chunked":
        request.environ["wsgi.input_terminated"] = True


# configure some logging
logging.basicConfig(format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s',
                    filename=os.path.join(BASE_DIR, LOG_DIR, 'server.log'))
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('root').setLevel(logging.WARNING)

class RequestFormatter(logging.Formatter):
    def format(self, record):
        record.url = request.url
        record.path = request.path
        record.full_path = request.full_path
        record.remote_addr = request.remote_addr
        return super().format(record)

FORMAT = RequestFormatter('[%(levelname)s] %(asctime)s - %(name)s - %(remote_addr)s %(full_path)s - %(message)s')
logger = logging.getLogger('lerc_server')
logger.propagate = False
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(FORMAT)
fh = logging.FileHandler(os.path.join(BASE_DIR, LOG_DIR, 'server.log'))
fh.setFormatter(FORMAT)
logger.addHandler(handler)
logger.addHandler(fh)


# begin helper functions #
class CustomRequestHandler(WSGIRequestHandler):
    # Just to log connections dropped when streaming a response
    def connection_dropped(self, error, environ=None):
        logging.warning('Connection dropped when streaming response data to client.')

def host_check(host, company, version=None):
    # known host?
    client = Clients.query.filter_by(hostname=host).first()
    try:
        comp = CompanyMapping.query.filter_by(id=company).one()
        if not comp:
            logger.warn("Company '{}' does not exist in fetch from hostname: {}".format(company, host))
    except Exception as e:
        logger.warn("No Company in database with ID:{} - fetch from hostname:{}".format(company, host))

    if client is None:
        new_client = Clients(host, company_id=company, sleep_cycle=15, version=version)
        db.session.add(new_client)
        db.session.commit()
        logger.info("Added {}/{} to client table".format(host, company))
        return new_client
    elif client.status == clientStatusTypes.UNINSTALLED:
        logger.info("Client being re-installed.")
        client.status = clientStatusTypes.ONLINE
        client.install_date = datetime.utcnow()
        client.last_activity = datetime.utcnow()
        client.company_id=company
        client.sleep_cycle=15
        db.session.commit()
        return client
    elif client.company_id != company:
        if client.company_id is None:
            logger.info("setting company_id for {}".format(host))
            client.company_id = company
            client.status = clientStatusTypes.ONLINE
            client.last_activity = datetime.utcnow()
            db.session.commit()
            return client
        logger.error("Company id mismatch for {}. Two clients with the same hostname in different environments?".format(host))
        client.status = clientStatusTypes.UNKNOWN
        db.session.commit()
        return False
    else:
        client.status = clientStatusTypes.ONLINE
        client.last_activity = datetime.utcnow()
        client.version = version
        db.session.commit()
        return client

def command_manager(host, remove_cid=None):
    if remove_cid:
        command = Commands.query.filter_by(hostname=host, command_id=remove_cid).one()
        db.session.delete(command)
        db.session.commit()
        logger.info("Removed command id:{} for host:{}".format(remove_cid, host))
        return True
    # An error occured somewhere if a client fetched without a command moving out of the STARTED state
    started_command = Commands.query.filter(Commands.hostname==host).filter(Commands.status==cmdStatusTypes.STARTED).order_by(Commands.command_id.asc()).first()
    if started_command:
        # XXX Maybe write code that attempts to recover the STARTED but not COMPLETE command
        logger.error("{} fetched without finishing CID={} - Changing command statue to UNKNOWN.".format(started_command.hostname, started_command.command_id))
        started_command.status = cmdStatusTypes.UNKNOWN
        started_command.evaluated_time = datetime.utcnow()
        db.session.commit()
    # Any open commands?
    command = Commands.query.filter(Commands.hostname==host).filter(Commands.status==cmdStatusTypes.PENDING).order_by(Commands.command_id.asc()).first()
    if command:
        if command.operation == operationTypes.UPLOAD:
            if command.server_file_path is None:
                filename = command.client_file_path
                filename = filename[filename.rfind('\\')+1:]
                command.server_file_path = "{}{}_{}_{}".format(DATA_DIR, command.hostname, command.command_id, filename)
                # add DEFAULT_CLIENT_DIR if it appears a path is not supplied
                if '\\' not in command.client_file_path:
                    command.client_file_path = DEFAULT_CLIENT_DIR + command.client_file_path
                db.session.commit()
            elif os.path.exists(os.path.join(BASE_DIR,command.server_file_path)):
                # handling edge case where db didn't get updated correctly after data transfer
                statinfo = os.stat(os.path.join(BASE_DIR,command.server_file_path))
                if statinfo.st_size > (command.file_position - 1) and statinfo.st_size != 0:
                    command.file_position = statinfo.st_size + 1
                    # Likly a connection drop and resume before server reached timeout
                    logger.warning("CID={} : More bytes found on server than recorded in database. Updating database to recover.".format(command.command_id))
                    db.session.commit()
        elif command.operation == operationTypes.DOWNLOAD:
            if '\\' not in command.client_file_path:
                ''' lerc.exe's writed files to c:\windows\system32 by defaut, so, change to DEFAULT_CLIENT_DIR
                    if not specified by the analyst when the command was issued '''
                command.client_file_path = DEFAULT_CLIENT_DIR + command.client_file_path
                db.session.commit()
        elif command.operation == operationTypes.RUN:
            if DEFAULT_CLIENT_DIR not in command.command:
                command.command = 'cd "'+DEFAULT_CLIENT_DIR+'" && '+command.command
            else:
                # if the DEFAULT_CLIENT_DIR already in the command then this is an indication the
                # client is fetching a command it fetched previously but the command wasn't recorded as reaching completion.
                # this scenario should be rare but may indicate a problem.. especially if it happens more than once with the same command/host
                if 'taskkill' in command.command:
                    logger.error("Host:{} fetched command id:{} again and it appears the command was to kill a process. This command coule be causing CRITICAL_PROCESS_DIED blue screens on the client.".format(host, command.command_id))
                else:
                    logger.warn("Host:{} fetched command id:{} again. Something may be preventing the commands completion.".format(host, command.command_id))
            db.session.commit()
        return command
    return None


def receive_streamed_data(command):
    # Write a file to the server - return None on Sucess, else error message
    stream_error = None
    chunk_size = CHUNK_SIZE
    # to make up for the design limitation of Werkzeug/wsgi_mod for streaming chunked data
    # gonna do this hack
    total_chunks, remaining_bytes = divmod(command.filesize - command.file_position, chunk_size)
    with open(os.path.join(BASE_DIR,command.server_file_path), 'ba') as f:
        for i in range(total_chunks):
            try:
                chunk = request.stream.read(chunk_size)
                # leaving the following len check in for native mode
                if len(chunk) == 0:
                    break
                f.write(chunk)
            except Exception as e:
                 stream_error = type(e).__name__ + " - " + str(e)
                 break
        try:
            final_chunk = request.stream.read(remaining_bytes)
            f.write(final_chunk)
        except OSError as e:  #request data read error
            stream_error = "Stream closed pre-maturely. ({})".format(str(e))
        f.close()
    return stream_error


def update_file_position(command):
    if command.server_file_path is not None:
        try:
            statinfo = os.stat(os.path.join(BASE_DIR,command.server_file_path))
            if command.file_position != statinfo.st_size and command.file_position <= command.filesize:
                command.file_position = statinfo.st_size + 1
                logger.info("updating file_position for {} to {}".format(command.command_id, command.file_position))
                db.session.commit()
        except FileNotFoundError as e:
            logger.warning("{} not found on server.".format(command.server_file_path))
# End helper functions #


# Begin server API for client resources
class Fetch(Resource):
    def get(self):

        version = request.args.get('version')
        host = request.args.get('host')
        company = request.args.get('company')

        if not host:
            logger.error("Malformed Fetch")
            return None
        if not company:
            logger.error("Malformed Fetch")
            return None

        client = host_check(host, int(company), version=version)

        if not client:
            # if something is not right, always issue sleep
            return ci.Sleep(DEFAULT_SLEEP)

        command = command_manager(host)

        if command:
            logger.info("Issuing {} to {}".format(command.operation, command.hostname))
            if command.operation == operationTypes.RUN:
                return ci.Run(command.command_id, command.command, async=command.async_run)
            elif command.operation == operationTypes.UPLOAD:
                return ci.Upload(command.command_id, command.client_file_path, command.file_position)
            elif command.operation == operationTypes.DOWNLOAD:
                return ci.Download(command.command_id, command.client_file_path)
            elif command.operation == operationTypes.QUIT:
                command.status = cmdStatusTypes.COMPLETE
                command.evaluated_time = datetime.utcnow()
                client = Clients.query.filter_by(hostname=host).first()
                client.status = clientStatusTypes.UNINSTALLED
                db.session.commit()
                return ci.Quit()

        # default: tell client to do nothing - make sure sleep_cycle is default
        logger.info("Issuing Sleep({}) to {}".format(DEFAULT_SLEEP, host))
        client.sleep_cycle = DEFAULT_SLEEP
        db.session.commit()
        return ci.Sleep(DEFAULT_SLEEP)


class Pipe(Resource):
    def post(self):
        if 'host' not in request.args:
            logger.error("Malformed pipe request")
            return None
        elif 'id' not in request.args:
            logger.error("Missing command id in pipe post from {}".format(request.args['host']))
            return None
        elif 'size' not in request.args:
            logger.error("Missing size in pipe post from {}".format(request.args['host']))

        cid = request.args['id']
        host = request.args['host']
        command = Commands.query.filter_by(hostname=host, command_id=cid).one()
        logger.info("Receiving Run command result from {}: ".format(host))
        command.server_file_path = "{}{}_RUN_{}".format(DATA_DIR, host, cid)
        post_size = UGLY_CHUNKSIZE
        if 'size' in request.args:
            post_size = int(request.args['size'])
        command.filesize = command.filesize + post_size
        command.status = cmdStatusTypes.STARTED
        # update last_activity and status
        client = Clients.query.filter_by(hostname=host).one()
        client.status = clientStatusTypes.BUSY
        client.last_activity = datetime.utcnow()
        db.session.commit()

        # Note: the client posts run results as they come in or after a certain timeout with no output from running command
        #   it will post a size=0&done=false as a "keep-alive" for the server
        if post_size > 0:
            stream_error = receive_streamed_data(command)
            logger.info("Received data written to '{}'".format(command.server_file_path))

        cmd_status_flag_done = None
        if 'done' in request.args:
            cmd_status_flag_done = True if request.args['done'] == 'true' else False

        # check the done flag for command completion
        if command.status == cmdStatusTypes.PENDING:
            if cmd_status_flag_done:
                command.status = cmdStatusTypes.COMPLETE
                command.evaluated_time = datetime.utcnow()
                logging.info("Command status set to COMPLETE for command {}".format(cid))
            elif 'done' not in request.args:
                logging.warning("DONE flag missing from arguments for command {}".format(cid))
                command.status = cmdStatusTypes.COMPLETE
                command.evaluated_time = datetime.utcnow()
            else:
                command.status = cmdStatusTypes.STARTED
                logging.info("Command status set to STARTED for command {}".format(cid))
        if command.status == cmdStatusTypes.STARTED and cmd_status_flag_done:
            command.status = cmdStatusTypes.COMPLETE
            command.evaluated_time = datetime.utcnow()
            logging.info("Command status set to COMPLETE for command {}".format(cid))
        #statinfo = os.stat(os.path.join(BASE_DIR, command.server_file_path))
        db.session.commit()
        return True


class Upload(Resource):
    def post(self):
        if 'host' not in request.args:
            logger.error("Malformed Upload request")
            return None
        elif 'id' not in request.args:
            logger.error("Missing command id in upload post from {}".format(request.args['host']))
            return None

        cid = request.args['id']
        host = request.args['host']

        # get status of this command
        command = Commands.query.filter_by(hostname=host, command_id=cid).one()
        if 'size' in request.args and request.args['size'] != command.filesize:
            command.filesize = request.args['size']
            db.session.commit()
        if command.file_position > 0:
            logger.info("Resuming upload with {} at byte {}".format(host, command.file_position))
        else:
            logger.info("Receiving Upload result from {} for command {}".format(host, cid))

        command.status = cmdStatusTypes.STARTED
        # update last_activity and status
        client = Clients.query.filter_by(hostname=host).one()
        client.status = clientStatusTypes.BUSY
        client.last_activity = datetime.utcnow()
        db.session.commit()
        stream_error = receive_streamed_data(command)

        # validating completion
        statinfo = os.stat(os.path.join(BASE_DIR,command.server_file_path))
        if stream_error is not None:
            # update the file position so the upload can be resumed
            command.file_position = statinfo.st_size + 1
            db.session.commit()
            logger.warning("Upload command {} Exception : '{}' | -> {} out of {} bytes received. Resuming on next fetch from host.".format(
                                                              command.command_id, stream_error, statinfo.st_size, command.filesize))
        elif statinfo.st_size == command.filesize or statinfo.st_size+1 == command.filesize:
            # Note that sometimes large files on unix show up a byte less in size than on NTFS windows
            logger.info("Upload command {} completed sucessfully - file: {}".format(command.command_id,
                                                                                    command.server_file_path))
            command.status = cmdStatusTypes.COMPLETE
            command.evaluated_time = datetime.utcnow()
            db.session.commit()
        else:
            logger.warn("{} indicates upload command {} complete, however, {}/{} filesize mismatch".format(host, command.command_id,
                                                                                               statinfo.st_size, command.filesize))
            command.status = cmdStatusTypes.UNKNOWN
            command.evaluated_time = datetime.utcnow()
            db.session.commit()
        return True


class Download(Resource):
    def get(self):
        if 'host' not in request.args or 'id' not in request.args or 'position' not in request.args:
            logger.error("Malformed Download request")
            return None

        cid = request.args['id']
        host = request.args['host']

        logger.info("Sending Download to {} for command {}".format(host, cid))
        
        command = Commands.query.filter_by(hostname=host, command_id=cid).one()
        command.file_position = int(request.args['position'])
        try:
            statinfo = os.stat(os.path.join(BASE_DIR, command.server_file_path))
        except FileNotFoundError as e:
            logger.error("FileNotFoundError: {} on this server".format(str(e)))
            command.status = cmdStatusTypes.ERROR
            command.evaluated_time = datetime.utcnow()
            command.log_file_path = "FileNotFoundError"
            db.session.commit()
            return Response()
        # This should really only detect when someone runs the exact same Download command
        if command.file_position == statinfo.st_size:
            logger.warning("File at same path and of same size is already on {}. Previously repeated command?".format(host))
            command.status = cmdStatusTypes.COMPLETE
            command.evaluated_time = datetime.utcnow()
            db.session.commit()
            logger.info("Download command {} completed successfully".format(command.command_id))
            return Response()

        def stream_response():
            error_message = None
            chunk_size = CHUNK_SIZE
            try:
                with open(os.path.join(BASE_DIR, command.server_file_path), 'rb') as f:
                    f.seek(command.file_position)
                    data = f.read(chunk_size)
                    while data:
                        yield data
                        data = f.read(chunk_size)
            except Exception as e:
                error_message = str(e)

            if error_message is None:
                command.status = cmdStatusTypes.COMPLETE
                command.evaluated_time = datetime.utcnow()
                db.session.commit()
                logger.info("Download command {} completed successfully".format(command.command_id))
            else:
                logger.warning("Exception encountered for Download command {} : '{}'".format(
                                                                           command.command_id,
                                                                           error_message))

        command.status = cmdStatusTypes.STARTED
        # update last_activity and status
        client = Clients.query.filter_by(hostname=host).one()
        client.status = clientStatusTypes.BUSY
        client.last_activity = datetime.utcnow()
        db.session.commit()
        return Response(stream_with_context(stream_response()))


class Error(Resource):
    def post(self):
        if 'host' not in request.args:
            logger.error("Malformed Error request")
            return None
        elif 'id' not in request.args:
            logger.error("Missing command id in Error post from {}".format(request.args['host']))
            return None
        cid = request.args['id']
        host = request.args['host']
        error_message = ""
        chunk_size = UGLY_CHUNKSIZE
        while True:
            try:
                chunk = request.stream.read(chunk_size)
                # leaving for native mode (werkzeug.streaming)
                if len(chunk) == 0:
                    break
                error_message = error_message + chunk.decode("utf-8")
            except OSError as e:
                # We tried to read a byte past the stream, we're done.
                break
            except Exception as e:
                logger.error("An Exception of type {} occured when receiving error from {}: {}".format(type(e).__name__,
                                                                                                       host, str(e)))
                break
        logger.warn("Error message from host={} for command_id={} : '{}'".format(host, cid, error_message))

        # update the command
        command = Commands.query.filter_by(hostname=host, command_id=cid).one()
        command.log_file_path = "{}{}_{}_ERROR.log".format(CLIENT_ERROR_DIR, host, cid)
        # XXX So far, I've been unable to figure out why this happens with large transfers
        if 'Unable to read data from the transport connection' in error_message or \
           'Unable to write data to the transport connection' in error_message:
            logger.info("Changing CID={} status from {} to PENDING so it correctly resumes.".format(cid, command.status))
            command.status = cmdStatusTypes.PENDING
        else:
            command.status = cmdStatusTypes.ERROR
            command.evaluated_time = datetime.utcnow()
        # update last_activity
        client = Clients.query.filter_by(hostname=host).one()
        client.last_activity = datetime.utcnow()
        db.session.commit()
        error_log = {'time': datetime.now(pytz.utc).strftime('%Y-%m-%d %H:%M:%S%z'),
                     'command_id': str(command.command_id),
                     'host': str(host),
                     'operation': str(command.operation.name),
                     'server file path': str(command.server_file_path),
                     'client file path': str(command.client_file_path),
                     'command': str(command.command),
                     'error': str(error_message)}
        with open(os.path.join(BASE_DIR, command.log_file_path), 'w') as f:
            json.dump(error_log, f)
        return False
# end client api resources


# begin analyst management api resource definitions
class Query(Resource):
    CMD_FIELDS = ['cmd_id', 'hostname', 'operation', 'cmd_status', 'client_id']
    CLIENT_FIELDS = ['client_id', 'hostname', 'client_status', 'version', 'company_id', 'company']
    FIELDS = list(set(CMD_FIELDS + CLIENT_FIELDS))
    def get(self):
        """Get command and client information from the server with the following search fields.
        This provides very basic 'AND' only queries. Fields are negated when a minus '-' sign is found in front of their values. 

        :cmd_id: Command id (Will return a specifc command id)
        :hostname: LERC hostname
        :cmd_status: commands with this status. 
        :client_id: LERC client id
        :operation: Commands of this operation type
        :client_status: Query for clients with a certain status
        :version: Query for client versions
        :company_id: Query for clients by company id
        :company: Query for clients by company name
        """
        logger.info("Analyst performing command query : {}".format(request.args))
        for key in request.args.keys():
            if key in self.FIELDS:
                break
        else:
            logger.error("Malformed command query request")
            return make_response("Missing command query arguments", 400)

        # Only perform queries if it makes sense to do so
        perform_client_query = False
        for key in request.args.keys():
            if key in self.CLIENT_FIELDS:
                perform_client_query = True
                break
        # A special rc argument must be set to inform 
        # the server that command results are wanted
        return_commands = request.args.get('rc')
        if not perform_client_query and not return_commands:
            logger.warn("Query will not return results : {}".format(request.args))
            return make_response("Bad Query: return_commands not set and no client arguments supplied.", 400)
        
        cmd_id = request.args.get('cmd_id')
        client_id = request.args.get('client_id')
        hostname = request.args.get('hostname')
        cmd_status = request.args.get('cmd_status')
        op = request.args.get('operation')
        client_status = request.args.get('client_status')
        version = request.args.get('version')
        company_id = request.args.get('company_id')
        company = request.args.get('company')

        results = {}
        results['clients'] = []
        results['commands'] = []

        # client results
        if perform_client_query:
            if company:
                negated = False
                if company[0] == '-':
                    negated = True
                    company = company[1:]
                comp = CompanyMapping.query.filter_by(name=company).one()
                if company_id and comp.id != int(company_id):
                    logger.warn("Analyst query argument conflict : company_id and company name")
                company_id = str(comp.id)
                if negated:
                    company_id = '-'+company_id

            query = Clients.query
            if client_id:
                if client_id[0] == '-':
                    query = query.filter(Clients.id!=client_id[1:])
                else:
                    query = query.filter(Clients.id==client_id)
            if hostname:
                if hostname[0] == '-':
                    query = query.filter(Clients.hostname!=hostname[1:])
                else:
                    query = query.filter(Clients.hostname==hostname)
            if client_status:
                if client_status[0] == '-':
                    query = query.filter(Clients.status!=client_status[1:])
                else:
                    query = query.filter(Clients.status==client_status)
            if version:
                if version[0] == '-':
                    query = query.filter(Clients.version!=version[1:])
                else:
                    query = query.filter(Clients.version==version)
            if company_id:
                if company_id[0] == '-':
                    query = query.filter(Clients.company_id!=company_id[1:])
                else:
                    query = query.filter(Clients.company_id==company_id)
            clients = query.all()
            results['clients'] = [client.to_dict() for client in clients]
            if not results['clients']:
                # For convienience -- lerc_api.lerc_session.get_hosts()
                clients = Clients.query.all()
                results['client_id_list'] = [client.id for client in clients]

        # command results
        if return_commands:
            query = Commands.query
            if cmd_id:
                if cmd_id[0] == '-':
                    query = query.filter(Commands.command_id!=cmd_id[1:])
                else:
                    query = query.filter(Commands.command_id==cmd_id)
            if client_id:
                if client_id[0] == '-':
                    query = query.filter(Commands.client_id!=client_id[1:])
                else:
                    query = query.filter(Commands.client_id==client_id)
            if hostname:
                if hostname[0] == '-':
                    query = query.filter(Commands.hostname!=hostname[1:])
                else:
                    query = query.filter(Commands.hostname==hostname)
            if cmd_status:
                if cmd_status[0] == '-':
                    query = query.filter(Commands.status!=cmd_status[1:])
                else:
                    query = query.filter(Commands.status==cmd_status)
            if op:
                if op[0] == '-':
                    query = query.filter(Commands.operation!=op[1:])
                else:
                    query = query.filter(Commands.operation==op)

            commands = query.all()

            if len(commands) == 1:
                # lerc_api.Command.refresh()
                # update file_position to report on any transfer progress that's occured
                update_file_position(commands[0])

                command = commands[0].to_dict()
                # include any existing error report
                log_file_path = command['log_file_path']
                if log_file_path:
                    with open(os.path.join(BASE_DIR, log_file_path), 'r') as f:
                        command['error'] = json.loads(f.read())
                else: # No error log file
                    command['error'] = None
                results['commands'] = [command]
            else:
                results['commands'] = [command.to_dict() for command in commands]

        return results


class Command(Resource):
    def post(self):
        # for posting new client commands and resources
        def custom_response(status_code, message, command_id=None, command=None):
            return {'status_code': status_code,
                    'message': message,
                    'command_id': command_id,
                    'command': command}

        client_id = request.args.get('id')
        host = request.args.get('host')

        if not host and not client_id:
            logger.error("Malformed Error request")
            return make_response("Missing arguments", 400)

        # make sure host exists in client tabel
        client = Clients.query.filter_by(hostname=host).first()
        if not client:
            if client_id:
                client = Clients.query.filter_by(id=client_id).one()
                if not client:
                    return {'status_code':'404',
                            'message': "Not Found",
                            'error': "No LERC client with id '{}'.".format(client_id)}
            else:
                return {'status_code':'404',
                        'message': "Not Found",
                        'error': "No LERC client installed on a host by name '{}'.".format(host)}

        if not request.is_json:
            logger.error("Command request is not json")
            return make_response("Command request is not json", 400)

        command = request.json

        logger.info("Receiving Analyst command for {}".format(host))

        if command['operation'].upper() == operationTypes.RUN.name:
            new_command = Commands(host, operationTypes.RUN, client_id=client.id, command=command['command'], async_run=command['async'])
            db.session.add(new_command)
            db.session.commit()
            logger.info("RUN command id {} created for {}".format(new_command.command_id, host))
            return custom_response(200, 'Created run command', command_id=new_command.command_id, command=new_command.to_dict())
        elif command['operation'].upper() == operationTypes.UPLOAD.name:
            new_command = Commands(host, operationTypes.UPLOAD, client_id=client.id, client_file_path=command['client_file_path'])
            db.session.add(new_command)
            db.session.commit()
            logger.info("UPLOAD command id {} created for {}".format(new_command.command_id, host))
            return custom_response(200, 'created upload command', command_id=new_command.command_id, command=new_command.to_dict())
        elif command['operation'].upper() == operationTypes.DOWNLOAD.name:
            if command['client_file_path'] is None:
                command['client_file_path'] = command['server_file_path']
            new_command = Commands(host, operationTypes.DOWNLOAD, client_id=client.id,
                                   client_file_path=command['client_file_path'],
                                   analyst_file_path=command['analyst_file_path'],
                                   server_file_path=DATA_DIR+command['server_file_path'])
            db.session.add(new_command)
            db.session.commit()
            logger.info("DOWNLOAD command id {} created for {}".format(new_command.command_id, host))
            return custom_response(200, 'created download command', command_id=new_command.command_id, command=new_command.to_dict())
        elif command['operation'].upper() == operationTypes.QUIT.name:
            new_command = Commands(host, operationTypes.QUIT, client_id=client.id)
            db.session.add(new_command)
            db.session.commit()
            logger.info("QUIT command id {} created for {}".format(new_command.command_id, host))
            return custom_response(200, 'created quit command', command_id=new_command.command_id, command=new_command.to_dict())

        return None 

    def get(self):
        ## XXX Deprecated - Replaced by Query. Leaving here for now
        # command/host status and result retrival
        host = None
        if 'host' not in request.args and 'cid' not in request.args and 'hid' not in request.args:
                logger.error("Malformed command request")
                return make_response("Missing arguments", 400)
        if 'cid' not in request.args:
            if 'host' in request.args:
                # if only host argument, return host and host's command queue
                logger.info("Sending analyst the command queue for host: {}".format(request.args['host']))
                client = Clients.query.filter_by(hostname=request.args['host']).first()
                if not client:
                    logger.warn("No client by name '{}'".format(request.args['host']))
                    return {'status_code':'404',
                            'message': "Not Found",
                            'error': "Client '{}' does not exist.".format(request.args['host'])}
                commands = Commands.query.filter_by(hostname=request.args['host'])
                return {'commands': [ command.to_dict() for command in commands ],
                        'client': client.to_dict()}
            elif 'hid' in request.args:
                logger.info("Sending analyst the command queue for host with host id: {}".format(request.args['hid']))
                client = Clients.query.filter_by(id=request.args['hid']).first()
                if not client:
                    logger.warn("No client with id '{}'".format(request.args['hid']))
                    clients = Clients.query.all()
                    client_ids = [client.id for client in clients]
                    return {'status_code':'404',
                            'message': "Not Found",
                            'host_ids': client_ids,
                            'error': "Client with id '{}' does not exist.".format(request.args['hid'])}
                return client.to_dict()
        # else either cid and host in args or only cid in args. cid in args
        
        cid = request.args['cid']
        logger.debug("Analyst checking on command {}".format(cid))
        command = Commands.query.filter_by(command_id=cid).first()
        if not command:
            return {'status_code':'404',
                    'message': "Not Found OR Gone",
                    'error': "Command id '{}' does not exist.".format(cid)}

        # update the host to check in more frequntly during this analyst session
        client = Clients.query.filter_by(hostname=command.hostname).one()
        if client.status == clientStatusTypes.UNKNOWN:
            return {'status_code': '409',
                    'error': 'Client state UNKNOWN. Review Server logs.',
                    'message': 'Conflict'}

        if client.sleep_cycle != 30:
            client.sleep_cycle = 30
            db.session.commit() 
            logger.info("Updated host '{}' sleep cycle to 30 seconds for analyst session.".format(client.hostname))

        if command.status == cmdStatusTypes.PREPARING and command.operation == operationTypes.DOWNLOAD:
            # Update file position as needed
            if os.path.exists(os.path.join(BASE_DIR,command.server_file_path)):
                statinfo = os.stat(os.path.join(BASE_DIR,command.server_file_path))
                command.file_position = statinfo.st_size
                db.session.commit()
        elif command.status == cmdStatusTypes.ERROR:
            result = command.to_dict()
            with open(os.path.join(BASE_DIR, command.log_file_path), 'r') as f:
                error_log = json.load(f)
            result['error'] = error_log['error']
            result['time'] = error_log['time']
            logger.debug("{} - {}".format(result['error'], result['time']))
            return result

        return command.to_dict()

class CancelCommand(Resource):
    def post(self):
        logger.info("Analyst attempting to cancel a command.")
        command_id = request.args.get('id')
        if not command_id:
            return make_response("Missing arguments", 400)
        command = Commands.query.filter(Commands.command_id==command_id).one()
        if command:
            command.status = cmdStatusTypes.CANCELED
            command.evaluated_time = datetime.utcnow()
            db.session.commit()
            return command.to_dict()
        return {'status_code':'404',
                'message': "Not Found",
                'error': "Command id '{}' does not exist.".format(command_id)}

class AnalystUpload(Resource):
    def post(self):
        host = request.args['host']
        cid = request.args['cid']

        command = Commands.query.filter_by(hostname=host, command_id=cid).first()
        if not command:
            return {'status_code':'404',
                    'message': "Not Found", 
                    'error': "Command id '{}' does not exist.".format(cid)}
        command.filesize = int(request.args['filesize'])


        # see if a file by the same name and md5 already exists 
        if os.path.exists(os.path.join(BASE_DIR,command.server_file_path)):
            # get md5 of file
            md5_hasher = md5()
            with open(os.path.join(BASE_DIR,command.server_file_path), 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5_hasher.update(chunk)
            file_md5 = md5_hasher.hexdigest().lower()

            if request.args['md5'] == file_md5:
                command.status = cmdStatusTypes.PENDING
                db.session.commit()
                logger.warn("File by same name and size already exists")
                command_dict = command.to_dict()
                command_dict['warn'] = "File by same name and md5 already exists on server at {}".format(command.server_file_path)
                return command_dict
            else:
                logger.warn("over writing file by same name but with different md5 hash")
                os.remove(os.path.join(BASE_DIR,command.server_file_path))

        stream_error = receive_streamed_data(command)

        # validating completion
        statinfo = os.stat(os.path.join(BASE_DIR,command.server_file_path))
        if stream_error is not None:
            # update the file position so the upload can be resumed
            command.file_position = statinfo.st_size + 1
            db.session.commit()
            logger.warning("Upload command {} Exception : '{}' | -> {} out of {} bytes received. Resuming on next fetch from host.".format(
                                                              command.command_id, stream_error, statinfo.st_size, command.filesize))
        elif statinfo.st_size == command.filesize or statinfo.st_size+1 == command.filesize:
            # Note that sometimes large files on unix show up a byte less in size than on NTFS windows
            logger.info("Sucessfully received file '{}' from analyst. Command now pending client fetch.".format(command.server_file_path))
            command.status = cmdStatusTypes.PENDING
            db.session.commit()
        else:
            logger.error("{} indicates upload command {} complete, however, {}/{} filesize mismatch".format(host, command.command_id,
                                                                                                  statinfo.st_size, command.filesize))
            command.status = cmdStatusTypes.UNKNOWN
            command.evaluated_time = datetime.utcnow()
            db.session.commit()

        return command.to_dict()

class AnalystDownload(Resource):
    def get(self):
        # stream results back to analyst
        def stream_results(command):
            chunk_size = CHUNK_SIZE
            logger.info("Streaming command {} results to analyst".format(command.command_id))
            try:
                with open(os.path.join(BASE_DIR, command.server_file_path), 'rb') as f:
                    f.seek(command.file_position)
                    data = f.read(chunk_size)
                    while data:
                        yield data
                        data = f.read(chunk_size)
            except Exception as e:
                logging.error(str(e))
                return False

        logger.debug("Analyst download request : {}".format(request.args))
        # Is the analyst making sure a result still exists?
        result_file_check = request.args.get('result')
        if result_file_check:
            if os.path.exists(os.path.join(BASE_DIR, result_file_check)):
                return {'message': "Results exist.", 'status_code': '200'}
            else:
                logger.warn("{} Does not exist".format(result_file_check))
                return {'status_code': '404',
                        'message': 'Not Found',
                        'error': 'Results do not exist at {} - note: old results are purged routinely'.format(result_file_check)} 

        if 'cid' not in request.args:
            logger.warn("Malformed analyst download request")
            return {'status_code': '400',
                    'message': 'Bad Request',
                    'error': 'missing required arguments'}
        cid = request.args['cid']
        command = Commands.query.filter_by(command_id=cid).first()
        if not command:
            return {'status_code':'404',
                    'message': "Not Found",
                    'error': "Command id '{}' does not exist.".format(cid)}

        get_error_report = request.args.get('error')
        if get_error_report:
            if command.log_file_path:
                error_report = None
                with open(os.path.join(BASE_DIR, command.log_file_path), 'r') as f:
                    error_report = json.loads(f.read())
                return error_report
            else: # No error log file
                return {'error': None}

        if 'position' not in request.args:
            logger.warn("Malformed analyst download request")
            return {'status_code': '400',
                    'message': 'Bad Request',
                    'error': 'missing required arguments'}

        #Make sure the result file exists - don't assume result_file_check happened correctly
        if not os.path.exists(os.path.join(BASE_DIR, command.server_file_path)):
            logger.warn("{} Does not exist".format(command.server_file_path))
            return None

        command.file_position = int(request.args['position'])
        if command.status == cmdStatusTypes.STARTED and command.operation == operationTypes.RUN:
            return Response(stream_with_context(stream_results(command)))

        if command.status != cmdStatusTypes.COMPLETE:
            logger.warn("Analyst attempting to get a command in state '{}'".format(command.status.name))
            result = command.to_dict()
            result['warn'] = "Command is not COMPLETE."
            return result

        return Response(stream_with_context(stream_results(command)))
# end analyst management resource definitions

# add client api resources
api.add_resource(Fetch, '/fetch')
api.add_resource(Pipe, '/pipe')
api.add_resource(Download, '/download')
api.add_resource(Upload, '/upload')
api.add_resource(Error, '/error')

# add analyst api resources
api.add_resource(Query, '/query')
api.add_resource(Command, '/command')
api.add_resource(CancelCommand, '/command/cancel')
api.add_resource(AnalystUpload, '/command/upload')
api.add_resource(AnalystDownload, '/command/download')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port='5000', request_handler=CustomRequestHandler)
