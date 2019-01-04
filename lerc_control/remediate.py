
import os

import logging

import lerc_api

logger = logging.getLogger("lerc_control."+__name__)

def delete_file(client, file_path):
    return False

def delete_registry(client, reg_path):
    return False

def delete_service(client, service_name):
    return False

def delete_scheduled_task(client, task_name):
    return False

def delete_directory(client, dir_path):
    return False

def kill_process(client, pname=None, pid=None):
    if pname is None and pid is None:
        logger.error("Must supply a process name or a process id to kill.")
        return False
    return False

def remediate(client, remediation_script):
    if not os.path.exists(remediation_script):
        logger.error("'{}' Does not exist".format(remediation_script))
        return False

    

