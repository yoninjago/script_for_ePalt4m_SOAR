import json
from unittest import mock

import pytest

OUTPUT = """{
  "ipv4": "10.54.20.79",
  "userName": "test_user",
  "dateFrom": "2023-06-20T07:36:33Z",
  "dateTo": "2024-06-20T07:36:33Z",
  "usbConnectEvents": [
    {
      "machineName": "Ubuntu-NB1",
      "dateTime": "2023-06-20T07:36:33Z",
      "vid": "090c",
      "pid": "1000",
      "userName": "test_user"
    }
  ]
}"""

JOURNALCTL_CMD_STDOUT = """
    2023-06-20T07:36:33+0000 Ubuntu-NB1 kernel: usb 3-5: new high-speed USB device number 12 using xhci_hcd
    2023-06-20T07:36:33+0000 Ubuntu-NB1 kernel: usb 3-5: New USB device found, idVendor=090c, idProduct=1000, bcdDevice=11.00
    2023-06-20T07:36:33+0000 Ubuntu-NB1 kernel: usb 3-5: New USB device strings: Mfr=1, Product=2, SerialNumber=3
    2023-06-20T07:36:33+0000 Ubuntu-NB1 kernel: usb 3-5: Product: USB Flash Disk
    2023-06-20T07:36:33+0000 Ubuntu-NB1 kernel: usb 3-5: Manufacturer: General
    2023-06-20T07:36:33+0000 Ubuntu-NB1 kernel: usb 3-5: SerialNumber: 0416060000013832
    2023-06-20T07:36:33+0000 Ubuntu-NB1 kernel: usb-storage 3-5:1.0: USB Mass Storage device detected
    2023-06-20T07:36:33+0000 Ubuntu-NB1 kernel: scsi host1: usb-storage 3-5:1.0
    2023-06-20T07:36:33+0000 Ubuntu-NB1 mtp-probe[116989]: checking bus 3, device 12: "/sys/devices/pci0000:00/0000:00:14.0/usb3/3-5"
    2023-06-20T07:36:33+0000 Ubuntu-NB1 mtp-probe[116989]: bus: 3, device: 12 was not an MTP device
    """


LAST_CMD_STDOUT = (
    'test_user :0           :0               Wed Jun 21 05:28:07 2023 - down                      (13:56)\n'
    'reboot   system boot  5.19.0-45-generic Wed Jun 21 05:25:45 2023 - Wed Jun 21 19:24:32 2023  (13:58)\n'
    'test_user :0           :0               Tue Jun 20 05:29:50 2023 - down                      (15:36)\n'
    'reboot   system boot  5.19.0-45-generic Tue Jun 20 05:14:15 2023 - Tue Jun 20 21:05:54 2023  (15:51)\n'
    'test_user :0           :0               Mon Jun 19 05:11:20 2023 - down                      (16:01)\n'
    )

target = __import__('usb_connect_events_linux')


@pytest.fixture(scope='function')
def script_input():
    input_json = {
        'ipv4': '10.54.20.79',
        'userName': 'test_user',
        'dateFrom': '2023-06-20T07:36:33Z',
        'dateTo': '2024-06-20T07:36:33Z'
        }
    ctx_obj = {'secrets': {
        'linux_login': 'user',
        'linux_password': 'password'
        }}
    return input_json, ctx_obj


@pytest.fixture(scope='function')
def mock_ssh():
    with mock.patch('usb_connect_events_linux.paramiko.SSHClient') as ssh:
        yield ssh.return_value


def get_exec_side_effect(journalctl_out, last_out):
    def _side_effect(cmd: str, *args, **kwargs):
        stdout = mock.MagicMock()
        stderr = mock.MagicMock()
        stderr.read().decode.return_value = None
        stdout.channel.recv_exit_status.return_value = 0
        if 'journalctl' in cmd:
            stdout.read().decode.return_value = journalctl_out
        elif 'last' in cmd:
            stdout.read().decode.return_value = last_out
        return (None, stdout, stderr)
    return _side_effect


def test_script_success_stdout(capsys, mock_ssh, script_input):
    mock_ssh.exec_command.side_effect = get_exec_side_effect(
        JOURNALCTL_CMD_STDOUT, LAST_CMD_STDOUT
        )
    target.main(*script_input)
    out, _ = capsys.readouterr()
    assert json.loads(out) == json.loads(OUTPUT)


@pytest.mark.parametrize(
    ('input_json', 'ctx_obj', 'result'),
    [
        ({},
         {'secrets': {
            'linux_login': 'test',
            'linux_password': '',
            }},
            'Отсутствуют секреты: linux_password'),
        ({'ipv4': ''},
         {'secrets': {
            'linux_login': 'test',
            'linux_password': 'test',
            }},
            'Отсутствуют обязательные входные аргументы: ipv4_or_hostname'),
    ],
)
def test_main_no_secrets_or_inputs(caplog, input_json, ctx_obj, result):
    with pytest.raises(SystemExit) as error:
        target.main(input_json, ctx_obj)
    assert error.value.code == 1
    assert result in caplog.text
