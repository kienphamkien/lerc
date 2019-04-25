#!/usr/bin/env python3

import unittest

#
import os
import sys
import time
from lerc_control import lerc_api, collect
from lerc_control.scripted import execute_script
from lerc_control.helpers import TablePrinter

# The hostname of the LERC client we're testing against
HOST = 'PCVNA3S171'

CLIENT_DIR = 'C:\\Temp\\'

CLIENT_FIELDS = ['hostname', 'status', 'install_date', 'company_id', 'last_activity', 'sleep_cycle', 'id', 'version']
COMMAND_FIELDS = ['command_id', 'hostname', 'client_id', 'operation', 'async_run', 'client_file_path', 'server_file_path', 'command', 'status', 'file_position', 'filesize', 'log_file_path', 'analyst_file_path']

# Default run command
CMD = 'echo "Hello, World!"'
DOWNLOAD_FILE_PATH = '/opt/lerc/.test_data/test_file.txt'
FILE_NAME = DOWNLOAD_FILE_PATH[DOWNLOAD_FILE_PATH.rfind('/')+1:]
# list of commands we run
COMMANDS = []

class TestLERC(unittest.TestCase):
    def setUp(self):
        self.ls = lerc_api.lerc_session()
        self.client = self.ls.get_host(HOST)

    def test_attach_client_valid(self):
        self.assertEqual(self.client.hostname, HOST)

    def test_run_command_creation(self):
        cmd = self.client.Run(CMD)
        self.assertEqual(cmd.hostname, HOST)
        self.assertTrue(isinstance(cmd.id, int))
        self.assertEqual(cmd.command, CMD)
        self.assertFalse(cmd.async_run)
        self.assertEqual(cmd.operation, 'RUN')
        COMMANDS.append(cmd)

    def test_async_run_command_creation(self):
        cmd = self.client.Run(CMD, async=True)
        self.assertEqual(cmd.hostname, HOST)
        self.assertTrue(isinstance(cmd.id, int))
        self.assertEqual(cmd.command, CMD)
        self.assertTrue(cmd.async_run)
        self.assertEqual(cmd.operation, 'RUN')
        COMMANDS.append(cmd)

    def test_download_command_creation(self):
        cmd = self.client.Download(DOWNLOAD_FILE_PATH, client_file_path=CLIENT_DIR+FILE_NAME)
        self.assertEqual(cmd.hostname, HOST)
        self.assertTrue(isinstance(cmd.id, int))
        self.assertEqual(cmd.operation, 'DOWNLOAD')
        COMMANDS.append(cmd)

    def test_upload_command_creation(self):
        # depends on last test being completed successfully
        cmd = self.client.Upload(CLIENT_DIR+FILE_NAME)
        self.assertEqual(cmd.hostname, HOST)
        self.assertTrue(isinstance(cmd.id, int))
        self.assertEqual(cmd.operation, 'UPLOAD')
        COMMANDS.append(cmd)

    def test_client_is_online(self):
        self.assertTrue(self.client.is_online)

    def test_wait_for_command(self):
        # It's important the client.is_online for this one
        cmd = COMMANDS[0]
        self.assertEqual(cmd.hostname, HOST)
        self.assertTrue(cmd.wait_for_completion())

    def test_get_results(self):
        for cmd in COMMANDS:
            if cmd.operation == 'RUN':
                cmd.wait_for_completion()
                if cmd.async_run:
                    # cmd should go to complete status but no data (get_results should return None)
                    self.assertIsNone(cmd.get_results(return_content=True))
                else:
                    results = cmd.get_results(return_content=True)
                    # should be the hello world echo
                    self.assertTrue(results.decode('utf-8')[:-1] in CMD)
                    # write the file
                    cmd.get_results(file_path='.test_data/RUN_CMD_'+str(cmd.id))
                    self.assertTrue(os.path.exists('/opt/lerc/.test_data/RUN_CMD_'+str(cmd.id)))
                    os.remove('/opt/lerc/.test_data/RUN_CMD_'+str(cmd.id))

    def test_error_reporting(self):
        # cause an error
        cmd = self.client.Upload('C:\\This\\Path\\IS\\Bad')
        cmd2 = self.client.Upload('C:\\Temp\\fake.txt')
        cmd.wait_for_completion()
        self.assertEqual(cmd.status, 'ERROR')
        error = cmd.get_error_report()
        self.assertIsInstance(error, dict)
        self.assertIn('Could not find a part of the path', error['error'])
        cmd2.wait_for_completion()
        self.assertEqual(cmd2.status, 'ERROR')
        error = cmd2.get_error_report()
        self.assertIn('Could not find file', error['error'])

    def test_command_get_dict(self):
        cmd = COMMANDS[0]
        self.assertTrue(isinstance(cmd.get_dict, dict))
        self.assertTrue(set(cmd.get_dict.keys()), set(COMMAND_FIELDS))

    def test_client_get_dict(self):
        self.assertTrue(isinstance(self.client.get_dict, dict))
        self.assertTrue(set(self.client.get_dict.keys()), set(CLIENT_FIELDS))

    def test_client_refresh(self):
        self.assertTrue(self.client.refresh())

    def test_client_list_directory(self):
        result = self.client.list_directory(CLIENT_DIR)
        self.assertTrue(isinstance(result, dict))
        self.assertTrue(set(result.keys()), set(['dir_lines', 'dir_size', 'drive_free_space', 'dir_dict']))

    def tearDown(self):
        # issue command to delete test file from test client
        cmd = 'cd "{}" && del {}'.format(CLIENT_DIR, FILE_NAME)
        self.client.Run(cmd)

if __name__ == '__main__':
    unittest.main(verbosity=2)
