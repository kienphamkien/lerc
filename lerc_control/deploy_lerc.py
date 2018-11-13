#!/usr/bin/env python3
#/data/home/carbonblack/env3/bin/python3

import os
import re
import sys
import time
import argparse
import datetime
import json
import pprint
import coloredlogs

from dateutil import tz
from configparser import ConfigParser

from cbapi import auth
from cbapi.response import *
from cbapi.errors import ApiError, ObjectNotFoundError, TimeoutError

import lerc_api
import logging, logging.config

# configure logging #
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
# set noise level
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('lerc_api').setLevel(logging.INFO)
logging.getLogger('cbapi').setLevel(logging.WARNING)

logger = logging.getLogger()
coloredlogs.install(level='DEBUG', logger=logger)


HOME_DIR = os.path.dirname(os.path.realpath(__file__)) 
#logging_config_path = os.path.join(HOME_DIR, 'etc', 'logging.ini')
#logging.config.fileConfig(logging_config_path)

def eastern_time(timestamp):
    eastern_timebase = tz.gettz('America/New_York')
    eastern_time = timestamp.replace(tzinfo=tz.gettz('UTC'))
    return eastern_time.astimezone(eastern_timebase).strftime('%Y-%m-%d %H:%M:%S.%f%z')


def go_live(sensor):
    start_time = time.time()
    timeout = 604800 # seven days
    current_day = 0
    lr_session = None
    while time.time() - start_time < timeout:
        try:
            lr_session = sensor.lr_session()
            logging.info("LR session started at {}".format(time.ctime()))
            break
        except TimeoutError:
            elapsed_time = time.time() - start_time
            if current_day != elapsed_time // 86400:
                current_day+=1
                logging.info("24 hours of timeout when polling for LR session")
                logging.info("Attempting LR session again on {} @ {}".format(args.sensor,
                                                                        time.ctime()))
    return lr_session


def deploy_lerc(sensor, install_cmd, lerc_installer_path=None):

    if not isinstance(sensor, models.Sensor):
        logging.error("Cb models.Sensor object required.")
        return False

    hostname = sensor.hostname
    default_lerc_path = '/opt/lerc_control/lercSetup.msi'
    if lerc_installer_path:
        default_lerc_path = lerc_installer_path

    lr_session = None
    try:
        logging.info(".. attempting to go live on the host with CarbonBlack..")
        lr_session = go_live(sensor)
    except Exception as e:
        logging.error("Failed to start Cb live response session on {}".format(hostname))
        return False

    # create lerc session
    ls = lerc_api.lerc_session()
    # check and see if the client's already installed
    result = None
    try:
        result = ls.check_host(hostname)
    except:
        logging.warning("Can't reach the lerc control server")

    previously_installed = proceed_with_force = None
    if result and 'client' in result:
        client = result['client']
        if client['status'] != 'UNINSTALLED':
            errmsg = "lerc server reports the client is already installed on a system with this hostname:\n{}"
            errmsg = errmsg.format(pprint.pformat(client))
            logging.warning(errmsg)
            proceed_with_force = input("Proceed with fresh install? (y/n) [n] ") or 'n'
            proceed_with_force = True if proceed_with_force == 'y' else False
            if not proceed_with_force:
                return
        else:
            previously_installed = True
            logging.info("A client was previously uninstalled on this host: {}".format(pprint.pformat(client)))

    with lr_session:

        if proceed_with_force:
            uninstall_cmd = "msiexec /x C:\Windows\Carbonblack\lercSetup.msi /quiet /qn /norestart /log C:\Windows\Carbonblack\lerc_Un-Install.log"
            logging.info("~ checking for installed lerc client on host..")
            result = lr_session.create_process("sc query lerc", wait_timeout=60, wait_for_output=True)
            result = result.decode('utf-8')
            logging.info("~ Got service query result:\n{}".format(result))
            if 'SERVICE_NAME' in result and 'lerc' in result:
                logging.info("~ attempting to uninstall lerc..")
                result = lr_session.create_process(uninstall_cmd, wait_timeout=60, wait_for_output=True)
                logging.info("~ Post uninstall service query:\n {}".format(lr_session.create_process("sc query lerc",
                                                                            wait_timeout=60, wait_for_output=True).decode('utf-8')))

        logging.info("~ dropping current Live Endpoint Response Client msi onto {}".format(hostname))
        filedata = None
        with open(default_lerc_path, 'rb') as f:
            filedata = f.read()
        try:
            lr_session.put_file(filedata, "C:\\Windows\\Carbonblack\\lercSetup.msi")
        except Exception as e:
            if 'ERROR_FILE_EXISTS' in str(e):
                logging.info("~ lercSetup.msi already on host. Deleting..")
                lr_session.delete_file("C:\\Windows\\Carbonblack\\lercSetup.msi")
                lr_session.put_file(filedata, "C:\\Windows\\Carbonblack\\lercSetup.msi")
                #pass
            else:
                raise e

        logging.info("~ installing the lerc service")
        result = lr_session.create_process(install_cmd, wait_timeout=60, wait_for_output=True)

    def _get_install_log(logfile=None):
        logging.info("Getting install log..")
        logfile = logfile if logfile else r"C:\\Windows\\Carbonblack\\lerc_install.log"
        content = lr_session.get_file(logfile)
        with open(hostname+"_lerc_install.log", 'wb') as f:
            f.write(content)
        logging.info("wrote log file to {}_lerc_install.log".format(hostname))


    wait = 5 #seconds
    attempts = 6
    if previously_installed:
        attempts += attempts
    logging.info("~ Giving client up to {} seconds to check in with the lerc control server..".format(attempts*wait))

    for i in range(attempts):
        try:
            result = ls.check_host(hostname)
        except:
            logging.warning("Can't reach the lerc control server")
            break
        if result:
            if 'error' not in result:
                if result['client']['status'] != 'UNINSTALLED':
                    break
        logging.info("~ giving the client {} more seconds".format(attempts*wait - wait*i))
        time.sleep(wait)

    if not result:
        logging.warning("failed to auto-confirm install with lerc server.")
        _get_install_log()
        return None
    elif 'error' in result:
        logging.error("'{}' returned from server. Client hasn't checked in.".format(result['error']))
        _get_install_log()
        return False
    elif previously_installed and result['client']['status'] == 'UNINSTALLED':
        logger.warning("Failed to auto-confirm install. Client hasn't checked in.")
        _get_install_log()
        return False

    client = result['client'] 
    logging.info("Client installed on {} at '{}' - status={} - last check-in='{}'".format(hostname,
                                 client['install_date'], client['status'], client['last_activity']))
    return result


def main(argv):

    parser = argparse.ArgumentParser(description="put file on CB sensor")
    parser.add_argument('company', choices=auth.CredentialStore("response").get_profiles(),
                        help='specify an environment you want to work with.')

    parser.add_argument('hostname', help="the name of the host to deploy the client to")
    parser.add_argument('-p', '--package', help="the msi lerc package to install")
    args = parser.parse_args()

    print(time.ctime() + "... starting")

    # ignore the proxy
    del os.environ['http_proxy']
    del os.environ['https_proxy']

    default_lerc_path = '/opt/lerc/lercSetup.msi'
    if args.package:
        default_lerc_path = args.package

    # lazy hack
    default_profile = auth.default_profile
    default_profile['lerc_install_cmd'] = None
    config = auth.CredentialStore("response").get_credentials(profile=args.company)

    cb = CbResponseAPI(profile=args.company) 

   # Get the right sensor 
    sensor = None
    try:
        logging.debug("Getting the sensor object from carbonblack")
        sensor = cb.select(Sensor).where("hostname:{}".format(hostname)).one()
    except TypeError as e:
        # Appears to be bug in cbapi library here -> site-packages/cbapi/query.py", line 34, in one
        # Raise MoreThanOneResultError(message="0 results for query {0:s}".format(self._query))
        # That raises a TypeError 
        if 'non-empty format string passed to object' in str(e):
            try: # accounting for what appears to be an error in cbapi error handling
                result = cb.select(Sensor).where("hostname:{}".format(hostname))
                if isinstance(result[0], models.Sensor):
                    print()
                    logging.warn("MoreThanOneResult Error searching for {0:s}".format(hostname))
                    print("\nResult breakdown:")
                    sensor_ids = []
                    for s in result:
                        sensor_ids.append(int(s.id))
                        if int(s.id) == max(sensor_ids):
                            sensor = s
                        print()
                        print("Sensor object - {}".format(s.webui_link))
                        print("-------------------------------------------------------------------------------\n")
                        print("\tos_environment_display_string: {}".format(s.os_environment_display_string))
                        print()
                        print("\tstatus: {}".format(s.status))
                        print("\tsensor_id: {}".format(s.id))
                        print("\tlast_checkin_time: {}".format(s.last_checkin_time))
                        print("\tnext_checkin_time: {}".format(s.next_checkin_time))
                        print("\tsensor_health_message: {}".format(s.sensor_health_message))
                        print("\tsensor_health_status: {}".format(s.sensor_health_status))
                        print("\tnetwork_interfaces:")
                    print()
                    default_sid = max(sensor_ids)
                    choice_string = "Which sensor do you want to use?\n"
                    for sid in sensor_ids:
                        choice_string += "\t- {}\n".format(sid)
                    choice_string += "\nEnter one of the sensor ids above. Default: [{}]".format(default_sid)
                    user_choice = int(input(choice_string) or default_sid)
                    for s in result:
                        if user_choice == int(s.id):
                            sensor = s
                            break
            except Exception as e:
                logging.error("{}".format(str(e)))
                return False
    except Exception as e:
        logging.error("{}".format(str(e)))
        return False


    result = deploy_lerc(sensor, config['lerc_install_cmd'], lerc_installer_path=default_lerc_path)
    if result:
        print()
        pprint.pprint(result['client'], indent=4)
        print()



if __name__ == "__main__":
    result = main(sys.argv[1:])
    if result != 1:
        print(time.ctime() + "...Done.")
    sys.exit(result)
