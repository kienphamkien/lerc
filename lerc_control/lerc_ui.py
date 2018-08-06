#!/usr/bin/python3

import os
import sys
import time
import argparse
import logging
import lerc_api
from pprint import pformat

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
logging.getLogger('requests').setLevel(logging.DEBUG)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('lerc_api').setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="User interface to the LERC control server")
    parser.add_argument('hostname', help="the host you'd like to work with")

    subparsers = parser.add_subparsers(dest='instruction')

    parser_run = subparsers.add_parser('run', help="Run a shell command on the host. BE CAREFUL!")
    parser_run.add_argument('command', help='The shell command for the host to execute`')

    parser_upload = subparsers.add_parser('upload', help="Upload a file from the client to the server")
    parser_upload.add_argument('file_path', help='the file path on the client')

    parser_download = subparsers.add_parser('download', help="Download a file from the server to the client")
    parser_download.add_argument('file_path', help='the path to the file on the server')
    parser_download.add_argument('-f', '--local-file', help='where the client should write the file')

    parser_quit = subparsers.add_parser('quit', help="tell the client to shutdown")

    parser_check = subparsers.add_parser('check', help="check on a specific command id")
    parser_check.add_argument('cid', help="the command id")

    args = parser.parse_args()

    # route direct
    if 'https_proxy' in os.environ:
        del os.environ['https_proxy']

    # this seems to only be neccessary for debian systems running in AWS
    #if 'REQUESTS_CA_BUNDLE' not in os.environ:
    #    logger.debug("setting 'REQUESTS_CA_BUNDLE' environment variable for HTTPS verification")
    #    os.environ['REQUESTS_CA_BUNDLE'] = os.path.join('/usr/local/share/ca-certificates/integral-ca.pem')

    host = args.hostname

    #server = 'https://control.local'
    ls = lerc_api.lerc_session(host=host)

    result = None
    if args.instruction == 'run':
        result = ls.Run(args.command)

    elif args.instruction == 'download':
        # if client_file_path is not specified the client will write the file to it's local dir
        file_name = args.file_path[args.file_path.rfind('/')+1:]
        if args.local_file is None:
            args.local_file = file_name
        result = ls.Download(file_name, args.local_file)

    elif args.instruction == 'upload':
        result = ls.Upload(args.file_path)

    elif args.instruction == 'quit':
        result = ls.Quit()
    elif args.instruction == 'check':
        print(ls.get_results(args.cid, chunk_size=16384))
        sys.exit()
    else:
        result = ls.get_command_queue()
        if 'error' in result:
            logger.error('\n{}'.format(pformat(result)))
            sys.exit()
        for command in result:
            print("{}\t{}".format(command['status'], command['operation']))
            if 'filesize' in command:
                print(command['filesize'])
        print()
        sys.exit()

    if ls.error:
        logger.error(ls.error)
        sys.exit(1)

    if 'command_id' not in result:
        logger.error(result)
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
        logger.error("From client: \n{}".format(pformat(command)))
        sys.exit(1)

    elif command['status'] == 'UNKNOWN':
        logger.error("The command is in an UNKNOWN state. An unknown error occured. Check the server logs")
        sys.exit(1)

    sys.exit()
