
import os
import logging
import configparser

logger = logging.getLogger("lerc_control."+__name__)

def delete_file(client, file_path):
    return client.Run('del "{}"'.format(file_path))

def delete_registry_key(client, reg_path):
    reg_key = reg_path[reg_path.rfind('\\')+1:]
    reg_path = reg_path[:reg_path.rfind('\\')]
    # issue commands for both 64 bit and 32 bit OS
    cmd = 'reg.exe DELETE {} /v {} /f /reg:64'.format(reg_path, reg_key)
    return client.Run(cmd) 

def delete_service(client, service_name):
    return False

def delete_scheduled_task(client, task_name):
    return False

def delete_directory(client, dir_path):
    return False

def kill_process_name(client, process):
    # will kill all processes by a given name
    return client.Run('taskkill /IM "{}" /F'.format(process))

def kill_process_id(client, pid):
    return client.Run('taskkill /F /PID {}'.format(pid))

def remediate(client, remediation_script):
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
                'registry_keys': []}

    # Order matters
    processes = config['process_names']
    for p in processes:
        commands['process_names'].append(kill_process_name(client, processes[p]))

    pids = config['pids']
    for p in pids:
        commands['pids'].append(kill_process_id(client, pids[p]))

    regs = config['registry_keys']
    for key in regs:
        commands['registry_keys'].append(delete_registry_key(client, regs[key]))

    files = config['files'] 
    for f in files:
        commands['files'].append(delete_file(client, files[f]))

    # XXX Get error results when commands go to error state
    # Wait on results and report
    for cmd in commands['process_names']:
        cmd_pname = cmd.command[cmd.command.find('"')+1:cmd.command.rfind('"')]
        # get the process name that is killed in this command, should be single results
        pname = [p for p in [processes[p] for p in processes] if p == cmd_pname][0]
        cmd.wait_for_completion()
        results = cmd.get_results(return_content=True)
        results = results.decode('utf-8')
        if cmd.status != 'COMPLETE':
            logger.error('Problem killing {}'.format(pname))
        elif 'SUCCESS' in results:
            logger.info("'{}' process names killed successfully : {}".format(pname, results))
        else:
            logger.warn("'{}' process names problem killing : {}".format(pname, results))

    for cmd in commands['pids']:
        pid = [p for p in [pids[p] for p in pids] if p in cmd.command][0]
        cmd.wait_for_completion()
        results = cmd.get_results(return_content=True)
        results = results.decode('utf-8')
        if cmd.status != 'COMPLETE':
            logger.error('Problem killing process id {}'.format(pid))
        elif 'SUCCESS' in results:
            logger.info("process id '{}' killed successfully : {}".format(pid, results))
        else:
            logger.warn("problem killing process id '{}' : {}".format(pid, results))

    for cmd in commands['registry_keys']:
        # get rkey that has path and key in cmd.command
        _cmd_str = cmd.command
        rkey = [r for r in [regs[r] for r in regs] if r[r.rfind('\\')+1:] in _cmd_str and r[:r.rfind('\\')] in _cmd_str][0]
        cmd.wait_for_completion()
        results = cmd.get_results(return_content=True)
        results = results.decode('utf-8')
        if cmd.status != 'COMPLETE':
            logger.error("Problem deleting '{}'".format(rkey))
        elif 'success' not in results:
            logger.warn("Problem deleting '{}' : {}".format(rkey, results))
        else:
            logger.info("Deleted '{}' : {}".format(rkey, results))

    for cmd in commands['files']:
        fname = [f for f in [files[f] for f in files] if f in cmd.command][0]
        cmd.wait_for_completion()
        results = cmd.get_results(return_content=True)
        if cmd.status != 'COMPLETE':
            logger.error("Problem deleting '{}'".format(fname))
        if results is not None:
            logger.warn("Problem deleting '{}' : {}".format(fname, results.decode('utf-8')))
        else:
            logger.info("File '{}' deleted successfully.".format(fname))

