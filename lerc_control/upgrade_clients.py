#!/usr/bin/python3

import os
import sys
import time
import argparse
import logging
import coloredlogs
import pprint

import lerc_api

from configparser import ConfigParser

# configure logging #
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
# set noise level
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('lerc_api').setLevel(logging.INFO)

logger = logging.getLogger('upgrade_clients')
coloredlogs.install(level='DEBUG', logger=logger)


def load_config(profile='default'):
    config = ConfigParser()
    config_paths = []
    config_paths.append(os.path.join(os.getcwd(),'etc','lerc.ini'))
    config_paths.append('/opt/lerc_control/etc/lerc.ini')
    config_paths.append('/opt/lerc/lerc_control/etc/lerc.ini')
    for cp in config_paths:
        try:
            if os.path.exists(cp):
                config.read(cp)
                logger.debug("Reading config file at {}.".format(cp))
                break
        except:
            pass
    else:
        logger.critical("No configuration file defined along search paths: {}".format(config_paths))

    try:
        config[profile]
    except:
        logger.critical("No section named '{}' in configuration file".format(profile))
        sys.exit(1)
    return config


def upgrade_host(hostname, upgrade_bat_path, lerc_msi_path):
    """ Upgrade steps """
    # Drop lercSetup.msi
    # Drop upgrade.bat 
    # Execute upgrade.bat async=True with correct params ex. -> upgrade.bat 0 15 2048 "https://your-server-address/"
    #     -> company=0 reconnectdelay=15 chunksize=2048 serverurls="https://your-server-address/"
    # Issue Quit command to host

    # keep track of all commands for each host

    host_commands = []

    ls = lerc_api.lerc_session()
    host_data = ls.check_host(hostname)
    if 'error' in host_data:
        logging.error(pprint.pformat(host_data))
        sys.exit(1)
    host = host_data['client']
    pprint.pformat(host)
    logger.info("Issuing upgrade commands to {}".format(hostname))

    # delete any existing lercSetup.msi that might already be on the host
    result = ls.Run("DEL lercSetup.msi")
    host_commands.append(result)

    file_name = lerc_msi_path[lerc_msi_path.rfind('/')+1:]
    result = ls.Download(file_name, client_file_path=file_name, analyst_file_path=lerc_msi_path)
    host_commands.append(result)

    file_name = upgrade_bat_path[upgrade_bat_path.rfind('/')+1:]
    result = ls.Download(file_name, client_file_path=file_name, analyst_file_path=upgrade_bat_path)
    host_commands.append(result)

    run_cmd = config[profile]['upgrade_cmd']
    result = ls.Run(run_cmd.format(host['company_id']), async=True)
    host_commands.append(result)

    result = ls.Quit()
    host_commands.append(result)
    return host_commands

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="A script to upgrade clients with a new lerc version.")
    parser.add_argument('-f', '--file', action="store", help="specify the path to a lercSetup.msi (default used from config file)")
    parser.add_argument('-d', '--debug', action="store_true", help="set logging to DEBUG")
    parser.add_argument('-e', '--environment', action="store_true", help="only upgrade hosts in a certain environment.")
    parser.add_argument('-c', '--client-hostname', action='store', help="upgrade this specific client, only")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger('lerc_api').setLevel(logging.DEBUG)
        coloredlogs.install(level='DEBUG', logger=logger)

    profile=args.environment if args.environment else 'default'
    config = load_config(profile)
    if 'ignore_system_proxy' in config[profile]:
        if config[profile].getboolean('ignore_system_proxy'):
            # route direct
            if 'https_proxy' in os.environ:
                del os.environ['https_proxy']

    if 'upgrade_bat' not in config[profile]:
        logger.error("missing upgrade_bat in config: must have path to upgrade.bat file")
        sys.exit(1)

    upgrade_bat_path = config[profile]['upgrade_bat']
    lerc_msi_path = config[profile]['client_installer']
    for path in [upgrade_bat_path, lerc_msi_path]:
        if not os.path.exists(path):
            logger.error("Does not exist: {}".format(path))
            sys.exit(1)

    if args.client_hostname:
        commands = upgrade_host(args.client_hostname, upgrade_bat_path, lerc_msi_path)
        with open(args.client_hostname+"_upgrade.log", 'w') as fh:
            fh.write(pprint.pformat(commands))
        sys.exit()

    ls = lerc_api.lerc_session()
    host_commands = {}
    for host in ls.get_hosts():
        if host['hostname'] == 'WIN-1TMIV79KTI8' or host['hostname'] == 'icinga' \
                                                 or host['hostname'] == 'W7GOTCHAPC':
            continue
        if host['status'] != 'UNINSTALLED':
            host_commands[host['hostname']] = upgrade_host(host['hostname'], upgrade_bat_path, lerc_msi_path)

    print(pprint.pformat(host_commands))

    sys.exit()
