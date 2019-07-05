import os
import time
import types
import logging
import progressbar

from lerc_control.lerc_api import CONFIG, check_config

# Get the working lerc_control directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logger = logging.getLogger("lerc_control."+__name__)

class TablePrinter(object):
    """Print a list of dicts as a table.

    :param fmt: list of tuple(heading, key, width)
    :param sep: string, separation between columns
    :param ul: string, character to underline column label, or None for no underlining
    :return: A string representation of the table, ready to be printed

    Each tuple in the fmt list of tuples is like so:

    :heading: str, column label
    :key: dictionary key to value to print
    :width: int, column width in chars
    """
    def __init__(self, fmt, sep=' ', ul=None):
        super(TablePrinter,self).__init__()
        self.fmt   = str(sep).join('{lb}{0}:{1}{rb}'.format(key, width, lb='{', rb='}') for heading,key,width in fmt)
        self.head  = {key:heading for heading,key,width in fmt}
        self.ul    = {key:str(ul)*width for heading,key,width in fmt} if ul else None
        self.width = {key:width for heading,key,width in fmt}

    def row(self, data):
        return self.fmt.format(**{ k:str(data.get(k,''))[:w] for k,w in self.width.items() })

    def __call__(self, dataList):
        _r = self.row
        res = [_r(data) for data in dataList]
        res.insert(0, _r(self.head))
        if self.ul:
            res.insert(1, _r(self.ul))
        return '\n'.join(res)


def wait_for_completion_and_display_any_transfer_progress(cmd, desc=None):
    if cmd.operation.lower() not in ['download', 'upload']:
        logger.info("Not a transfer command.")
        return cmd.wait_for_completion()
    if desc is None:
        desc = "CMD:{} - {} progress: [".format(cmd.id, cmd.operation)
    if not cmd.started:
        logger.info("Waiting for command to move from {} to STARTED..".format(cmd.status))
    while not cmd.started:
        if not cmd.progress():
            return cmd.wait_for_completion()
        time.sleep(1)

    if cmd.started and cmd.filesize == 0:
        logger.warning("Unexpected command state and filesize combination.")
        return cmd.wait_for_completion()
    logger.info("Command {} has STARTED ..".format(cmd.id))

    pbar = progressbar.ProgressBar(maxval=cmd.filesize, widgets=[progressbar.Bar("=", desc, ']'), ' ', progressbar.Percentage()])
    pbar.term_width = int(pbar.term_width / 2)

    pbar.start()
    while not cmd.complete:
        pbar.update(cmd.file_position)
        if not cmd.progress():
            return cmd.wait_for_completion()
        time.sleep(0.5)
    pbar.finish()
    return True

def install_rekall(lerc, rekall_installer_path=None, rekall_install_command=None):
    """Install rekall on a client.
    """
    required_info = []
    if rekall_installer_path is None:
        required_info.append('rekall_installer_path')
    if rekall_install_command is None:
        required_info.append('rekall_install_command')

    if rekall_installer_path is not None:
        if not os.path.exists(rekall_installer_path):
            if rekall_installer_path[0] == '/':
                rekall_installer_path = BASE_DIR + rekall_installer_path
            else:
                rekall_installer_path = BASE_DIR + '/' + rekall_installer_path
        if not os.path.exists(rekall_installer_path):
            logger.error("Path to rekall installer does not exist: {}".format(rekall_installer_path))
            return False

    config = check_config(CONFIG, required_keys=required_info)
    if not config:
        logger.error("Missing rekall config items.")
        return False
        
    if rekall_install_command is None:
        rekall_install_command = config['default']['rekall_install_command'] if config.has_option('default', 'rekall_install_command') else rekall_install_command
        if lerc.profile != "default":
            rekall_install_command = config[lerc.profile]['rekall_install_command'] if config.has_option(lerc.profile, 'rekall_install_command') else rekall_install_command
    if rekall_installer_path is None:
        rekall_installer_path = config['default']['rekall_installer_path'] if config.has_option('default', 'rekall_installer_path') else rekall_installer_path
        if lerc.profile != "default":
            rekall_installer_path = config[lerc.profile]['rekall_installer_path'] if config.has_option(lerc.profile, 'rekall_installer_path') else rekall_installer_path

    downcmd = lerc.Download(rekall_installer_path, client_file_path='rekall_installer.exe')
    logger.info("Issued {} to download rekall_installer.exe on {}".format(downcmd.id, lerc.hostname))
    installcmd = lerc.Run(rekall_install_command)
    logger.info("Issued {} to install rekall on {}".format(installcmd.id, lerc.hostname))
    installcmd.wait_for_completion()
    return True