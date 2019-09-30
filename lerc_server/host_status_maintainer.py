#!/usr/bin/python3

import os
import time
import logging
import configparser
import pymysql
import pymysql.cursors

from datetime import datetime, timedelta


BASE_DIR = os.path.dirname(os.path.realpath(__file__))
LOG_DIR = 'logs/'
ETC_DIR = 'etc/'

config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, ETC_DIR, 'lerc_server.ini'))

# globals and config items
DB_server = config['lerc_server']['dbserver']
DB_user = config['lerc_server']['dbuser']
DB_userpass = config['lerc_server']['dbuserpass']
# offline_timeout = the ammount of time a host has been offline
#     before we change its status to UNKNOWN
offline_timeout = int(config['host_checker']['offline_timeout'])

# Connect to Db
db = pymysql.connect(DB_server, DB_user, DB_userpass, "lerc", 
                                        cursorclass=pymysql.cursors.DictCursor)

# configure some logging
logging.basicConfig(format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s',
                    filename=os.path.join(BASE_DIR, LOG_DIR, 'host_status.log'))
LOGGER = logging.getLogger('host_status_maintainer')
LOGGER.setLevel(logging.INFO)
logging.propagate = False


def status_update():

    try:
        with db.cursor() as c:
            # hostname - status - install_date - last_activity - sleep_cycle - company_id
            LOGGER.debug("Getting clients..")
            c.execute("SELECT * FROM clients")
            for client in c.fetchall():
                if client['status'] == "BUSY":
                    away_time = datetime.utcnow() - client['last_activity']
                    with db.cursor() as tmp_c:
                        tmp_c.execute("SELECT operation,command_id FROM commands WHERE hostname='{}' AND status='STARTED'".format(client['hostname']))
                        command = tmp_c.fetchone()
                        if command is None:
                            LOGGER.error("{} is in BUSY state with no STARTED commands in queue. Away time='{}' - Setting UNKNOWN".format(client['hostname'], away_time))
                            tmp_c.execute("UPDATE clients SET status='UNKNOWN' WHERE hostname='{}'".format(client['hostname']))
                        elif away_time > timedelta(seconds=client['sleep_cycle']+2):
                            c.execute("UPDATE clients SET status='OFFLINE' WHERE hostname='{}'".format(client['hostname']))
                            LOGGER.info("Set {} to OFFLINE: Exceeded it's next expected check-in by '{}'".format(client['hostname'],
                                                                         str(away_time - timedelta(seconds=client['sleep_cycle']))))
                        else:
                            LOGGER.info("{} is in a BUSY state working on CID={} since '{}'".format(client['hostname'], command['command_id'], client['last_activity']))
                elif client['status'] != "UNKNOWN" and client['status'] != "UNINSTALLED" and client['status'] != "OFFLINE":
                    away_time = datetime.utcnow() - client['last_activity']
                    LOGGER.debug("{} hasn't fetched in '{}'".format(client['hostname'], away_time))
                    if away_time > timedelta(days=offline_timeout):
                        c.execute("UPDATE clients SET status='UNKNOWN' WHERE hostname='{}'".format(client['hostname']))
                        LOGGER.warning("Set {} to UNKNOWN: It's '{}' passed the configured offline timeout".format(client['hostname'],
                                                                                   str(away_time - timedelta(days=offline_timeout))))
                    elif away_time > timedelta(seconds=client['sleep_cycle']+2): # add two seconds to account for small delays
                        c.execute("UPDATE clients SET status='OFFLINE' WHERE hostname='{}'".format(client['hostname']))
                        LOGGER.info("Set {} to OFFLINE: Exceeded it's next expected check-in by '{}'".format(client['hostname'],
                                                                         str(away_time - timedelta(seconds=client['sleep_cycle']))))

    finally:
        db.commit()
    return

if __name__ == '__main__':

    status_update()
    time.sleep(30)
    status_update()
    db.close()


