
import enum
import pytz
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Begin DB models #
class operationTypes(enum.Enum):
    RUN  = 'RUN'
    UPLOAD = 'UPLOAD'
    DOWNLOAD = 'DOWNLOAD'
    QUIT = 'QUIT'

class cmdStatusTypes(enum.Enum):
    PENDING = 'PENDING'
    STARTED = 'STARTED'
    COMPLETE = 'COMPLETE'
    UNKNOWN = 'UNKNOWN'
    ERROR = 'ERROR'
    CANCELED = 'CANCELED'
    PREPARING = 'PREPARING' # file transfer between analysis <-> crat server

class clientStatusTypes(enum.Enum):
    ONLINE = 'ONLINE'
    OFFLINE = 'OFFLINE'
    UNKNOWN = 'UNKNOWN'
    UNINSTALLED = 'UNINSTALLED'
    BUSY = 'BUSY'

class Commands(db.Model):
    command_id = db.Column(db.Integer, primary_key = True)
    hostname = db.Column(db.String(40))
    operation = db.Column(db.Enum(operationTypes))
    command = db.Column(db.String(1024))
    file_position = db.Column(db.Integer)
    filesize = db.Column(db.Integer, default=0)
    client_file_path = db.Column(db.String(1024))
    server_file_path = db.Column(db.String(1024))
    status = db.Column(db.Enum(cmdStatusTypes))
    log_file_path = db.Column(db.String(1024))
    analyst_file_path = db.Column(db.String(1024))
    async_run = db.Column(db.Boolean, default=False)
    client_id = db.Column(db.Integer)
    evaluated_time = db.Column(db.DateTime)

    def __init__(self, hostname, operation, client_id, client_file_path=None,
                 server_file_path=None, command=None, analyst_file_path=None, async_run=False):
       self.hostname = hostname
       self.operation = operation
       self.client_id = client_id
       self.client_file_path = client_file_path
       self.server_file_path = server_file_path
       self.analyst_file_path = analyst_file_path
       self.command = command
       self.async_run = async_run
       if operation == operationTypes.DOWNLOAD:
           self.status = cmdStatusTypes.PREPARING
       else:
           self.status = cmdStatusTypes.PENDING
       self.file_position = 0
       self.filesize = None
       self.log_file_path = None
       self.evaluated_time = None

    def to_dict(self):
        return {'command_id': self.command_id,
                'hostname': self.hostname,
                'client_id': self.client_id,
                'operation': self.operation.name,
                'async_run': self.async_run,
                'client_file_path': self.client_file_path,
                'server_file_path': self.server_file_path,
                'command': self.command,
                'status': self.status.name,
                'file_position': self.file_position,
                'filesize': self.filesize,
                'log_file_path': self.log_file_path,
                'evaluated_time': self.evaluated_time.replace(tzinfo=pytz.utc).strftime('%Y-%m-%d %H:%M:%S%z') if self.evaluated_time else None,
                'analyst_file_path': self.analyst_file_path}


class Clients(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    hostname = db.Column(db.String(40), index=True, unique=True)
    status = db.Column(db.Enum(clientStatusTypes))
    install_date = db.Column(db.DateTime)
    company_id = db.Column(db.Integer)
    last_activity = db.Column(db.DateTime)
    sleep_cycle = db.Column(db.Integer)
    version = db.Column(db.String(20))

    def __init__(self, hostname, status=clientStatusTypes.ONLINE, install_date=datetime.now(), company_id=0, sleep_cycle=60, version=None):
        self.hostname = hostname
        self.status = status
        self.install_date = install_date
        self.company_id = company_id
        self.last_activity = datetime.now()
        self.sleep_cycle = sleep_cycle
        self.version = version

    def to_dict(self):
        return {'hostname': self.hostname,
                'status': self.status.name,
                'install_date': self.install_date.replace(tzinfo=pytz.utc).strftime('%Y-%m-%d %H:%M:%S%z'),
                'company_id': self.company_id,
                'last_activity': self.last_activity.replace(tzinfo=pytz.utc).strftime('%Y-%m-%d %H:%M:%S%z'),
                'sleep_cycle': self.sleep_cycle,
                'id': self.id,
                'version': self.version}

       
class CompanyMapping(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(128), unique=True)

    def __init__(self, name):
        self.name = name

# End DB models #

