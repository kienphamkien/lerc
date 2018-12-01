#!/usr/bin/python3

import os
import sys
import time
import argparse
import logging
import coloredlogs
import pprint
import lerc_api

# will likely need to changes these local imports to lerc_control.* after pip3 setup is complete
import collect
import deploy_lerc

from scripted import execute_script

# configure logging #
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
# set noise level
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('lerc_api').setLevel(logging.INFO)

logger = logging.getLogger('lerc_ui')
coloredlogs.install(level='INFO', logger=logger)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="User interface to the LERC control server")
    parser.add_argument('hostname', help="the host you'd like to work with")
    parser.add_argument('-q', '--queue', action="store_true", help="return the entire command queue (despite status)")
    parser.add_argument('-e', '--environment', action="store", help="specify an environment to work with. Default='default'")
    parser.add_argument('-d', '--debug', action="store_true", help="set logging to DEBUG")

    subparsers = parser.add_subparsers(dest='instruction') #title='subcommands', help='additional help')

    parser_run = subparsers.add_parser('run', help="Run a shell command on the host. BE CAREFUL!")
    parser_run.add_argument('command', help='The shell command for the host to execute`')
    parser_run.add_argument('-a', '--async', action='store_true', help='Set asynchronous to true (do NOT wait for output or command to complete)')

    parser_collect = subparsers.add_parser('collect', help="Default (no argumantes): perform a full lr.exe collection")
    parser_collect.add_argument('-b', '--browsing-history', action='store_true', help='Collect browsing history with BrowsingHistoryView.exe')

    parser_upload = subparsers.add_parser('upload', help="Upload a file from the client to the server")
    parser_upload.add_argument('file_path', help='the file path on the client')

    parser_download = subparsers.add_parser('download', help="Download a file from the server to the client")
    parser_download.add_argument('file_path', help='the path to the file on the server')
    parser_download.add_argument('-f', '--local-file', help='where the client should write the file')

    parser_quit = subparsers.add_parser('quit', help="tell the client to uninstall itself")

    parser_check = subparsers.add_parser('check', help="check on a specific command id")
    parser_check.add_argument('cid', help="the command id")

    parser_resume = subparsers.add_parser('resume', help="resume a pending command id")
    parser_resume.add_argument('cid', help="the command id")

    parser_get = subparsers.add_parser('get', help="get results for a command id")
    parser_get.add_argument('cid', help="the command id")

    parser_contain = subparsers.add_parser('contain', help="Contain an infected host")
    parser_contain.add_argument('-on', action='store_true', help="turn on containment")
    parser_contain.add_argument('-off', action='store_true', help="turn off containment")
    parser_contain.add_argument('-s', '--status', action='store_true', help="Get containment status of host")

    parser_script = subparsers.add_parser('script', help="run a scripted routine on thie lerc.")
    parser_script.add_argument('-l', '--list-scripts', action='store_true', help="list built-in scripts availble to lerc_ui")
    parser_script.add_argument('-s', '--script-name', help="provide the name of a build in script to run")
    parser_script.add_argument('-f', '--file-path', help="the path to a custom script you want to execute")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger('lerc_api').setLevel(logging.DEBUG)
        coloredlogs.install(level='DEBUG', logger=logger)

    host = args.hostname
    # create a lerc session object and make sure the host exists
    # by checking for it and getting it's dict representation
    ls = lerc_api.lerc_session() 
    client = ls.check_host(host=host)

    profile=args.environment if args.environment else 'default'
    if args.instruction == 'collect':
        if not args.debug:
            logging.getLogger('lerc_api').setLevel(logging.WARNING)
        collect.full_collection(args.hostname, profile=profile)
        #pprint.pprint(commands)
        sys.exit(0)

    if args.instruction == 'script':
        #logging.getLogger('lerc_api').setLevel(logging.WARNING)
        config = lerc_api.load_config()
        if args.list_scripts:
            if not config.has_section('scripts'):
                print("\nNo pre-existing scripts have been made availble.")
                sys.exit(0)           
            print("\nAvailable scripts:")
            for sname in config['scripts']:
                print("\t{}".format(sname))
            print()
            sys.exit(0)
        elif args.script_name:
            if not config.has_option('scripts', args.script_name):
                print("{} is not a defined script".format(args.script_name))
            script_path = config['scripts'][args.script_name]
            commands = execute_script(args.hostname, script_path)
            sys.exit(0)
        elif args.file_path:
            if not os.path.exists(args.file_path):
                logger.error("Could not find script file at '{}'".format(args.file_path))
                sys.exit(1)
            commands = execute_script(args.hostname, args.file_path)
            sys.exit(0)
        else:
            logger.info("No argument was specified for the script command. Exiting.")
            sys.exit(0)

    result = None
    if args.instruction == 'run':
        if args.async:
            print(args.async)
            result = ls.Run(args.command, async=args.async)
        else:
            result = ls.Run(args.command)

    elif args.instruction == 'contain':
        if args.on:
            ls.contain()
        elif args.off:
            ls.release_containment()
        elif args.status:
            print("Containment status check not yet implemented.")

    elif args.instruction == 'download':
        # if client_file_path is not specified the client will write the file to it's local dir
        analyst_file_path = os.path.abspath(args.file_path)
        file_name = args.file_path[args.file_path.rfind('/')+1:]
        if args.local_file is None:
            args.local_file = file_name
        result = ls.Download(file_name, client_file_path=args.local_file, analyst_file_path=analyst_file_path)

    elif args.instruction == 'upload':
        result = ls.Upload(args.file_path)

    elif args.instruction == 'quit':
        result = ls.Quit()
    elif args.instruction == 'check':
        command = ls.check_command(args.cid)
        if command:
            pprint.pprint(command)
        sys.exit()
    elif args.instruction == 'get':
        command = ls.get_results(args.cid, chunk_size=16384)
        if command:
            pprint.pprint(command)
        sys.exit()
    elif args.instruction == 'resume':
        command = ls.check_command(args.cid)
        command = ls.wait_for_command(command)
        if command:
            pprint.pprint(command)
        sys.exit()
    elif args.queue:
        result = ls.get_command_queue()
        if 'error' in result:
            logger.error('\n{}'.format(pprint.pformat(result)))
            sys.exit()
        if not result:
            print("This host doesn't have any command history.")
        for command in result:
            pprint.pprint(command)
        print()
        sys.exit()
    else:
        client = ls.check_host()
        pprint.pprint(client)
        print()
        sys.exit()

    if not result:
        sys.exit(1)

    start_time = time.time() 
    command = ls.check_command()
    command = ls.wait_for_command(command)

    if command['status'] == 'COMPLETE':
        if command['operation'] == 'UPLOAD':
            logger.info("Downloading file from server.")
            ls.get_results()
        elif command['operation'] == 'RUN':
            logger.info("Downloading command results..")
            ls.get_results()
        else:
            logger.info("{} command {} completed successfully".format(command['operation'], command['command_id']))

    elif command['status'] == 'ERROR':
        # get the error log file and write or print
        if not 'error' in command:
            logger.error("unexpected error condition without error message")
            sys.exit(1)
        logger.error("From client: \n{}".format(pprint.pformat(command)))
        sys.exit(1)

    elif command['status'] == 'UNKNOWN':
        logger.error("The command is in an UNKNOWN state. An unknown error occured. Check the server logs")
        sys.exit(1)
    else:
        print(pprint.pformat(command))

    sys.exit()
