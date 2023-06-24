# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Optional

import paramiko
import pytz
from paramiko.auth_handler import AuthenticationException

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] Event: %(message)s')
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


@dataclass
class SecretsConfig:
    """Config with sensitive information for ssh access

    :param linux_login: login to access the remote server
    :param linux_password: password to access the remote server
    """
    linux_login: str
    linux_password: str

    def __post_init__(self):
        check_inputs_objects(asdict(self), 'secrets')


@dataclass
class SshConfig:
    """Config with ssh access credentials

    :param ipv4_or_hostname: hostname or ipv4 address of the remote server
    :param ssh_port: optional param. Default 22
    """
    ipv4_or_hostname: str
    ssh_port: Optional[int] = 22

    def __post_init__(self):
        if self.ssh_port is None or not isinstance(self.ssh_port, int):
            self.ssh_port = 22
        check_inputs_objects(asdict(self), 'input')


@dataclass
class ScriptConfig:
    """Config with log filter params

    :param username: optional param. String with username
    :param date_from: optional param. Start date in the iso8601 format
    :param date_to: optional param. End date in the iso8601 format
    :param timezone: optional param. Timezone in the format like
        'Asia/Yekaterinburg'. Default value is UTC
    """
    username: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    timezone: Optional[str] = None

    def __post_init__(self):
        for date in (self.date_to, self.date_from):
            if date is None:
                continue
            if not is_valid_date(date):
                raise SystemError('Неправильный формат входных дат.')
        if self.timezone is None:
            self.timezone = 'UTC'
        if not is_valid_timezone(self.timezone):
            raise SystemError('Неправильный формат таймзоны.')


class CreateSSHConnectionError(Exception):
    """
    Exception raised by failures in authentication
    or connection or establishing an SSH session.
    """
    def __init__(self) -> None:
        super().__init__('Ошибка установки ssh соединения')


class ExecSSHCommandError(Exception):
    """Exeption raised when executing remote command failed."""
    def __init__(self, hostname: str) -> None:
        self.hostname = hostname
        super().__init__(
            f'Ошибка выполнения команды на удаленном сервере {self.hostname}')


class RemoteClient:
    """
    A class used to represent a ssh connection to remote host

    :param host: hostname or ip address of remote server
    :param login: user login for remote connection
    :param password: user password for remote connection
    :param port: ssh port. default 22 If not specified
    :param SSH_CONNECT_TIMEOUT: an optional timeout (in seconds)
        for the TCP connect
    :param EXEC_COMMAND_TIMEOUT: an optional timeout (in seconds)
        for execute command
    """

    SSH_CONNECT_TIMEOUT: int = 15
    EXEC_COMMAND_TIMEOUT: int = 50

    def __init__(self, host: str, login: str, password: str, port: int = 22):
        self.host = host
        self.login = login
        self.password = password
        self.port = port
        self._ssh = None

    def __create_connection(self):
        """Open SSH connection to remote host.

        :raises: CreateSSHConnectionError: if failed authentication
            or connection or establishing an SSH session
        """
        try:
            self._ssh = paramiko.SSHClient()
            self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._ssh.connect(
                hostname=self.host, username=self.login,
                password=self.password, port=self.port,
                look_for_keys=False, allow_agent=False,
                timeout=RemoteClient.SSH_CONNECT_TIMEOUT
                )
        except AuthenticationException as error:
            logger.error(f'Неудачная попытка аутентификации: {error}')
            raise CreateSSHConnectionError()
        except Exception as error:
            logger.error(
                'Проблемы с подключением к хосту '
                f'{self.host}:{self.port}: {error}'
                )
            raise CreateSSHConnectionError()

    def disconnect(self):
        """Close SSH connection."""
        if self._ssh is not None:
            self._ssh.close()

    def __enter__(self):
        self.__create_connection()
        return self

    def __exit__(self, exc_type: Exception, *args):
        self.disconnect()
        if exc_type is not None:
            return False
        return True

    def execute_commands(self, command: str, sudo_password: str = None) -> str:
        """
        Execute a command on the SSH server.

        :param command: unix command as a string
        :param sudo_password: if need run command with sudo and
            need password to authenticates
        :returns: string of the executing command stdout
        :raises: ExecSSHCommandError: if exit status code not equal 0
        """
        if self._ssh is None:
            self.__create_connection()
        logger.info(f'Запуск команды "{command}" на сервере {self.host}')
        stdin, stdout, stderr = self._ssh.exec_command(
            command, timeout=RemoteClient.EXEC_COMMAND_TIMEOUT
            )
        if 'sudo ' in command:
            stdin.write(f'{sudo_password}\n')
            stdin.flush()
        status_code = stdout.channel.recv_exit_status()
        server_answer = stdout.read().decode()
        error_message = stderr.read().decode()
        if status_code == 0:
            return server_answer
        else:
            logger.error(
                f'Выполнение команды "{command}" закончилось со статус кодом '
                f'"{status_code}". Содержание потока ошибок: "{error_message}"'
                )
            raise ExecSSHCommandError(self.host)


class USBStorageLogCMD:
    """
    Command to retrieve the connection logs of the USB Mass Storage device.
    """

    @staticmethod
    def _get_date(date_from: str, date_to: str) -> str:
        """
        Build query for time period filtration.

        :param date_from: start date in iso8601 format (%Y-%m-%dT%H:%M:%SZ)
        :param date_to: end date in iso8601 format (%Y-%m-%dT%H:%M:%SZ)
        :returns: empty string or string with date converting to
            valid linux cmd format (%Y-%m-%d %H:%M:%S)
        """
        if not date_from and not date_to:
            return ''
        query = ''
        if date_from:
            query += f'--since "{convert_date(date_from)}" '
        if date_to:
            query += f'--until "{convert_date(date_to)}" '
        return f'{query}'

    @staticmethod
    def buildCMD(config: ScriptConfig) -> str:
        """
        Complete command for get logs from journalctl.

        :param config: class with username, date_from, date_to,
            timezone arguments
        :returns: journalctl command for get USB Storage device connection logs
        """
        return (
            f'TZ={config.timezone} journalctl '
            f'{USBStorageLogCMD._get_date(config.date_from, config.date_to)}'
            '-o short-iso | grep "USB Mass Storage device detected" -B 7'
            )


def is_valid_timezone(timezone: str) -> bool:
    """Check timezone format

    :param timezone: string with timezone
    :returns: True if a valid timezone format (like 'Asia/Yekaterinburg'),
        else False
    """
    try:
        pytz.timezone(timezone)
        return True
    except pytz.exceptions.UnknownTimeZoneError:
        logger.error(f'Неправильный формат таймзоны: "{timezone}".')
        return False


def is_valid_date(date: str) -> bool:
    """checks the date matches the format iso8601

    :param date: string with date
    :returns: True if a valid date format (%Y-%m-%dT%H:%M:%SZ), else False
    """
    try:
        datetime.strptime(date, '%Y-%m-%dT%H:%M:%SZ')
        return True
    except ValueError:
        logger.error(
            f'Формат входящей даты "{date}" '
            'не совпадает с iso8601 (%Y-%m-%dT%H:%M:%SZ).'
            )
        return False


def convert_date(date: str) -> str:
    """Convert date from iso 8601 to linux command format

    :param date: Date in iso8601 format (%Y-%m-%dT%H:%M:%SZ)
    :returns: valid date format for linux commands (%Y-%m-%d %H:%M:%S)
    """
    return datetime.strptime(
        date, '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S')


def parse_usb_storage_connect_events(
        events: str) -> Optional[list[dict[str, str]]]:
    """Parse USB Storage device detected events from syslog.

    :param events: log entries from syslog as a string
    :returns: list of object with field machineName, dateTime, vid, pid.
        Or None if no relevant information is found.
    """
    regex = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}) (\S+) '
        r'.*idVendor=(\w+).*idProduct=(\w+)[\S\s]+?'
        r'USB Mass Storage device detected'
        )
    matches = regex.findall(events)
    if not matches:
        return None
    result = []
    for match in matches:
        date = datetime.strptime(
            match[0], '%Y-%m-%dT%H:%M:%S%z').strftime('%Y-%m-%dT%H:%M:%SZ')
        result.append({
            'machineName': match[1],
            'dateTime': date,
            'vid': match[2],
            'pid': match[3]
        })
    return result


def parse_logon_events(events: str) -> Optional[list[dict[str, str]]]:
    """Parse logon events from wtmp log.

    :param events: log entries from wtmp log as a string
    :returns: list of object with field userName, dateTimeIn, dateTimeOut.
        Or None if no relevant information is found.
    """
    entrys = events.splitlines()
    results = []
    for entry in entrys:
        if not entry or entry.startswith("reboot") or entry.startswith("wtmp"):
            continue
        result_login = {}
        columns = entry.split()
        match_login_time = re.search(
            r'\s+\w{3} (\w{3}\s+\d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \d{1,4})',
            entry)
        if match_login_time:
            login_time = datetime.strptime(
                match_login_time.group(1), '%b %d %H:%M:%S %Y')
            result_login['userName'] = columns[0]
            result_login["dateTimeIn"] = login_time.strftime(
                '%Y-%m-%dT%H:%M:%SZ')
        logout_time = ""
        match_logout_time = re.search(
            r'-\s+\w{3} (\w{3}\s+\d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \d{1,4})',
            entry)
        match_logged_in_time = re.search(
            r'(\((?P<days>\d+)\+|\()(?P<hours>\d+)\:(?P<minutes>\d+)\)',
            columns[-1])
        if match_logout_time:
            logout_time = datetime.strptime(
                match_logout_time.group(1), '%b %d %H:%M:%S %Y')
        elif match_logged_in_time:
            logout_time = login_time + timedelta(
                days=int(match_logged_in_time.groupdict(0)['days']),
                hours=int(match_logged_in_time.groupdict(0)['hours']),
                minutes=int(match_logged_in_time.groupdict(0)['minutes']))
        if logout_time:
            result_login['dateTimeOut'] = logout_time.strftime(
                '%Y-%m-%dT%H:%M:%SZ')
        elif 'still logged in' in entry:
            result_login['dateTimeOut'] = datetime.now().strftime(
                '%Y-%m-%dT%H:%M:%SZ')
        results.append(result_login)
    if not results:
        return None
    return results


def add_user_to_usb_connect_events(
        usb_events: list[dict[str, str]],
        login_events: list[dict[str, str]]) -> list[dict[str, str]]:
    """Add user to usb_events according to the field dateTime.

    :param usb_events: list of events with a mandatory field 'dateTime'
    :param login_events: list of events with a mandatory fields: 'dateTimeIn',
        'dateTimeOut', 'userName'
    :returns: usb_events with new field 'userName'.
    """
    for usb in usb_events:
        for login in login_events:
            if login['dateTimeIn'] < usb['dateTime'] < login['dateTimeOut']:
                usb['userName'] = login['userName']
    return usb_events


def filter_by_username(
        events: list[dict[str, str]], username: str) -> list[dict[str, str]]:
    """Filter events by username

    :param events: list of events objects with 'userName' field
    :param username: string with username for which you want to receive events
    :returns: list of events objects with required username
    """
    return [event for event in events if event.get('userName') == username]


def check_inputs_objects(objects: dict[str, str], object_type: str) -> None:
    """Check script input parameters for missing values.

    :param objects: script input params
    :param object_type: type of input object - secrets or input,
        for customize log message
    :returns: None
    :raises: SystemExit: if value of object is None
    """
    missing_objects = [obj for obj in objects.keys() if not objects[obj]]
    if missing_objects:
        if object_type == 'secrets':
            logger.critical(
                f'Отсутствуют секреты: {", ".join(missing_objects)}')
        else:
            logger.critical(
                'Отсутствуют обязательные входные аргументы:'
                f' {", ".join(missing_objects)}')
        raise SystemExit(1)


def main(input_json: dict, ctx_obj: dict):
    secrets = ctx_obj.get('secrets')
    secrets_config = SecretsConfig(
        linux_login=secrets.get('linux_login'),
        linux_password=secrets.get('linux_password')
        )
    input_config = SshConfig(
        ipv4_or_hostname=input_json.get('hostname') or input_json.get('ipv4'),
        ssh_port=int(input_json.get('ssh_port', 22))
        )
    script_config = ScriptConfig(
        username=input_json.get('userName'),
        date_from=input_json.get('dateFrom'),
        date_to=input_json.get('dateTo'),
        timezone=input_json.get('timezone')
    )
    try:
        with RemoteClient(
            input_config.ipv4_or_hostname,
            secrets_config.linux_login,
            secrets_config.linux_password,
            input_config.ssh_port
                ) as ssh_client:
            usb_events = ssh_client.execute_commands(
                USBStorageLogCMD.buildCMD(script_config))
            logon_events = ssh_client.execute_commands(
                f'TZ={script_config.timezone} last -F -w')
        usb_events = parse_usb_storage_connect_events(usb_events)
        if not usb_events:
            raise SystemExit(
                'Событий подключения USB Mass Storage device не найдено.')
        logon_events = parse_logon_events(logon_events)
        if logon_events:
            usb_events = add_user_to_usb_connect_events(
                usb_events, logon_events)
            if script_config.username:
                usb_events = filter_by_username(
                    usb_events, script_config.username
                    )
            if not usb_events:
                raise SystemExit(
                    'События подключения USB Mass Storage device найдены,'
                    ' но не соответствуют указанном username: '
                    f'{script_config.username}'
                    )
        input_json['usbConnectEvents'] = usb_events
        print(json.dumps(input_json))
    except CreateSSHConnectionError as error:
        raise SystemExit(error)
    except ExecSSHCommandError as error:
        raise SystemExit(f'{error} или не найдены события.')
    except Exception as error:
        logger.exception(f'Непредвиденная ошибка: {error}')


if __name__ == "__main__":
    main(json.loads(sys.argv[1]), json.loads(sys.argv[2]))
