
import os
import logging
import configparser

logger = logging.getLogger("lerc_control."+__name__)

REMEDIATION_TYPES = ['files', 'process_names', 'scheduled_tasks', 'services', 'directories', 'pids', 'registry_keys', 'registry_values']

def delete_file(client, file_path):
    return client.Run('del "{}"'.format(file_path))

def delete_registry_value(client, reg_path):
    reg_key = reg_path[reg_path.rfind('\\')+1:]
    reg_path = reg_path[:reg_path.rfind('\\')]
    # issue commands for both 64 bit and 32 bit OS
    cmd = 'REG DELETE "{}" /v "{}" /f'.format(reg_path, reg_key)
    return client.Run(cmd) 

def delete_registry_key(client, reg_path):
    cmd = 'REG DELETE "{}" /f'.format(reg_path)
    return client.Run(cmd)

def delete_service(client, service_name):
    return False

def delete_scheduled_task(client, task_name):
    return False

def delete_directory(client, dir_path):
    cmd = 'cd "{}" && DEL /F /Q /S * > NUL'.format(dir_path)
    cmd += ' && cd .. && RMDIR /Q /S "{}"'.format(dir_path)
    return client.Run(cmd)

def kill_process_name(client, process):
    # will kill all processes by a given name
    return client.Run('taskkill /IM "{}" /F'.format(process))

def kill_process_id(client, pid):
    return client.Run('taskkill /F /PID {}'.format(pid))

def evaluate_remediation_results(cmd, remediation_type, target_value):
    if remediation_type not in REMEDIATION_TYPES:
        raise ValueError("Invalid remediation type '{}'. Valid types: {}".format(remediation_type, REMEDIATION_TYPES))

    cmd.wait_for_completion()
    results = cmd.get_results(return_content=True)
    if remediation_type == 'process_names':
        pname = target_value
        results = results.decode('utf-8') if results is not None else None
        if cmd.status != 'COMPLETE':
            error_message = cmd.get_error_report()['error']
            logger.error('Problem killing {} : {}:{}'.format(pname, cmd.status, error_message))
        elif 'SUCCESS' in results:
            logger.info("'{}' process names killed successfully : {}".format(pname, results))
        else:
            logger.warn("'{}' process names problem killing : {}".format(pname, results))
    elif remediation_type == 'pids':
        pid = target_value
        results = results.decode('utf-8') if results is not None else None
        if cmd.status != 'COMPLETE':
            error_message = cmd.get_error_report()['error']
            logger.error('Problem killing process id {}'.format(pid, cmd.status, error_message))
        elif 'SUCCESS' in results:
            logger.info("process id '{}' killed successfully : {}".format(pid, results))
        else:
            logger.warn("problem killing process id '{}' : {}".format(pid, results))
    elif remediation_type == 'registry_values':
        rkey = target_value
        results = results.decode('utf-8') if results is not None else None
        if cmd.status != 'COMPLETE':
            error_message = cmd.get_error_report()['error']
            logger.error("Problem deleting '{}'".format(rkey, cmd.status, error_message))
        elif 'success' not in results:
            logger.warn("Problem deleting '{}' : {}".format(rkey, results))
        else:
            logger.info("Deleted '{}' : {}".format(rkey, results))
    elif remediation_type == 'registry_keys':
        rkey = target_value
        results = results.decode('utf-8') if results is not None else None
        if cmd.status != 'COMPLETE':
            error_message = cmd.get_error_report()['error']
            logger.error("Problem deleting '{}'".format(rkey, cmd.status, error_message))
        elif 'success' not in results:
            logger.warn("Problem deleting '{}' : {}".format(rkey, results))
        else:
            logger.info("Deleted '{}' : {}".format(rkey, results))
    elif remediation_type == 'files':
        fname = target_value
        if cmd.status != 'COMPLETE':
            error_message = cmd.get_error_report()['error']
            logger.error("Problem deleting '{}'".format(fname, cmd.status, error_message))
        if results is not None:
            logger.warn("Problem deleting '{}' : {}".format(fname, results.decode('utf-8')))
        else:
            logger.info("File '{}' deleted successfully.".format(fname))
    elif remediation_type == 'directories': 
       directory = target_value
       if cmd.status != 'COMPLETE':
            error_message = cmd.get_error_report()['error']
            logger.error("Problem deleting directory '{}' : {}".format(directory, cmd.status, error_message))
       elif results is not None:
            logger.warn("Problem deleting directory '{}' : {}".format(directory, results.decode('utf-8')))
       else:
            logger.info("Successfully deleted '{}'.".format(directory))


def Remediate(client, remediation_script):
    if not os.path.exists(remediation_script):
        logger.error("'{}' Does not exist".format(remediation_script))
        return False

    config = configparser.ConfigParser()
    config.read(remediation_script)

    commands = {'files': [],
                'process_names': [],
                'scheduled_tasks': [],
                'directories': [],
                'pids': [],
                'registry_keys': [],
                'registry_values': []}

    # Order matters
    processes = config['process_names']
    for p in processes:
        commands['process_names'].append(kill_process_name(client, processes[p]))

    pids = config['pids']
    for p in pids:
        commands['pids'].append(kill_process_id(client, pids[p]))

    regValues = config['registry_values']
    for key in regValues:
        commands['registry_values'].append(delete_registry_value(client, regValues[key]))

    regKeys = config['registry_keys']
    for key in regKeys:
        commands['registry_keys'].append(delete_registry_key(client, regKeys[key]))

    files = config['files'] 
    for f in files:
        commands['files'].append(delete_file(client, files[f]))

    dirs = config['directories']
    for d in dirs:
        commands['directories'].append(delete_directory(client, dirs[d]))

    # Wait on results and report
    for cmd in commands['process_names']:
        cmd_pname = cmd.command[cmd.command.find('"')+1:cmd.command.rfind('"')]
        # get the process name that is killed in this command, should be single results
        pname = [p for p in [processes[p] for p in processes] if p == cmd_pname][0]
        evaluate_remediation_results(cmd, 'process_names', pname)

    for cmd in commands['pids']:
        pid = [p for p in [pids[p] for p in pids] if p in cmd.command][0]
        evaluate_remediation_results(cmd, 'pids', pid)

    for cmd in commands['registry_values']:
        # get rkey that has path and key in cmd.command
        _cmd_str = cmd.command
        rvalue = [r for r in [regValues[r] for r in regValues] if r[r.rfind('\\')+1:] in _cmd_str and r[:r.rfind('\\')] in _cmd_str][0]
        evaluate_remediation_results(cmd, 'registry_values', rvalue)

    for cmd in commands['registry_keys']:
        rkey = [r for r in [regKeys[r] for r in regKeys] if r in cmd.command][0]
        evaluate_remediation_results(cmd, 'registry_keys', rkey)

    for cmd in commands['files']:
        fname = [f for f in [files[f] for f in files] if f in cmd.command][0]
        evaluate_remediation_results(cmd, 'files', fname)

    for cmd in commands['directories']:
        directory = [d for d in [dirs[d] for d in dirs] if d in cmd.command][0]
        evaluate_remediation_results(cmd, 'directories', directory) 
