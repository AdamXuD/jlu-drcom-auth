#!/usr/bin/env python3
import http.client
import logging
import os
import re
import signal
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from hashlib import md5
from random import randrange
from urllib.parse import urlsplit

PORT = 61440
DEFAULT_ONLINE_CHECK_URLS = (
    'http://connectivitycheck.platform.hicloud.com/generate_204,'
    'http://connectivitycheck.gstatic.com/generate_204'
)
log = logging.getLogger('jlu-drcom')


def required_env(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError(f'缺少环境变量 {name}')
    return value


def env_int(name, default, minimum=1):
    try:
        value = int(os.environ.get(name) or default)
    except ValueError:
        raise ValueError(f'{name} 必须是整数') from None
    if value < minimum:
        raise ValueError(f'{name} 必须大于或等于 {minimum}')
    return value


def env_hex(name, default):
    value = os.environ.get(name, default)
    if not re.fullmatch(r'[0-9a-fA-F]{%d}' % len(default), value):
        raise ValueError(f'{name} 必须是 {len(default)} 位十六进制')
    return bytes.fromhex(value)


def env_ipv4(name, default):
    try:
        return socket.inet_pton(socket.AF_INET, os.environ.get(name, default))
    except OSError:
        raise ValueError(f'{name} 必须是 IPv4 地址') from None


@dataclass(frozen=True, repr=False)
class Config:
    server: str
    username: bytes
    password: bytes
    mac: int
    host_name: bytes
    primary_dns: bytes
    dhcp_server: bytes
    control_check_status: bytes
    adapter_num: bytes
    ip_dog: bytes
    auth_version: bytes
    keep_alive_version: bytes
    retry_interval: int
    socket_timeout: int
    udp_attempts: int
    keep_alive_interval: int
    online_check_interval: int
    online_check_timeout: int
    online_check_fails: int
    online_check_urls: tuple[str, ...]

    @classmethod
    def from_env(cls):
        server = required_env('DRCOM_SERVER').strip()
        if not server:
            raise ValueError('DRCOM_SERVER 不能为空')
        username = required_env('DRCOM_USERNAME').encode()
        password = required_env('DRCOM_PASSWORD').encode()
        host_name = os.environ.get('DRCOM_HOST_NAME', 'linux-host').encode()
        for name, value, limit in (
            ('DRCOM_USERNAME', username, 36),
            ('DRCOM_PASSWORD', password, 16),
            ('DRCOM_HOST_NAME', host_name, 32),
        ):
            if len(value) > limit:
                raise ValueError(f'{name} 最多 {limit} 字节')

        mac = required_env('DRCOM_REGISTERED_MAC').strip().replace(':', '').replace('-', '')
        if not re.fullmatch(r'[0-9a-fA-F]{12}', mac):
            raise ValueError('DRCOM_REGISTERED_MAC 必须是 12 位十六进制 MAC 地址')

        online_check_urls = tuple(
            url.strip()
            for url in os.environ.get('DRCOM_ONLINE_CHECK_URLS', DEFAULT_ONLINE_CHECK_URLS).split(',')
            if url.strip()
        )
        for url in online_check_urls:
            try:
                parts = urlsplit(url)
                if parts.scheme not in ('http', 'https') or not parts.hostname:
                    raise ValueError
            except ValueError:
                raise ValueError('DRCOM_ONLINE_CHECK_URLS 必须填写 HTTP 或 HTTPS URL') from None

        return cls(
            server=server,
            username=username,
            password=password,
            mac=int(mac, 16),
            host_name=host_name,
            primary_dns=env_ipv4('DRCOM_PRIMARY_DNS', '10.10.10.10'),
            dhcp_server=env_ipv4('DRCOM_DHCP_SERVER', '0.0.0.0'),
            control_check_status=env_hex('DRCOM_CONTROLCHECKSTATUS', '20'),
            adapter_num=env_hex('DRCOM_ADAPTERNUM', '03'),
            ip_dog=env_hex('DRCOM_IPDOG', '01'),
            auth_version=env_hex('DRCOM_AUTH_VERSION', '6800'),
            keep_alive_version=env_hex('DRCOM_KEEP_ALIVE_VERSION', 'dc02'),
            retry_interval=env_int('DRCOM_CHECK_INTERVAL', 30),
            socket_timeout=env_int('DRCOM_SOCKET_TIMEOUT', 10),
            udp_attempts=env_int('DRCOM_MAX_UDP_RETRIES', 3),
            keep_alive_interval=env_int('DRCOM_KEEP_ALIVE_INTERVAL', 10),
            online_check_interval=env_int('DRCOM_ONLINE_CHECK_INTERVAL', 10, minimum=0),
            online_check_timeout=env_int('DRCOM_ONLINE_CHECK_TIMEOUT', 5),
            online_check_fails=env_int('DRCOM_ONLINE_CHECK_FAILS', 1),
            online_check_urls=online_check_urls,
        )


class DrcomError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_real_online(config):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for url in config.online_check_urls:
        request = urllib.request.Request(url, headers={'Cache-Control': 'no-cache'})
        try:
            with opener.open(request, timeout=config.online_check_timeout) as response:
                status = response.getcode()
                if status == 204 or ('generate_204' not in url and 200 <= status < 300):
                    return True
        except urllib.error.HTTPError as exc:
            exc.close()
        except (OSError, http.client.HTTPException, ValueError):
            continue
    return False


def checksum(data):
    # Keep the checksum calculation used by the original JLU login packet.
    result = 1234
    for word in re.findall(b'....', data):
        result ^= int.from_bytes(word, 'little')
    return struct.pack('<I', (1968 * result) & 0xffffffff)


def build_login_packet(config, salt, host_ip):
    digest = md5(b'\x03\x01' + salt + config.password).digest()
    mac_field = config.mac.to_bytes(max(1, (config.mac.bit_length() + 7) // 8), 'big')
    mac_xor = int.from_bytes(digest[:6], 'big') ^ config.mac
    data = b'\x03\x01\x00' + bytes([len(config.username) + 20])
    data += digest + config.username.ljust(36, b'\x00')
    data += config.control_check_status + config.adapter_num + mac_xor.to_bytes(6, 'big')
    data += md5(b'\x01' + config.password + salt + b'\x00' * 4).digest()
    data += b'\x01' + host_ip + b'\x00' * 12
    data += md5(data + b'\x14\x00\x07\x0b').digest()[:8]
    data += config.ip_dog + b'\x00' * 4
    data += config.host_name.ljust(32, b'\x00') + config.primary_dns + config.dhcp_server
    data += b'\x00' * 12
    data += struct.pack('<5I', 0x94, 6, 2, 0x23f0, 2)
    data += b'DrCOM\x00\xcf\x07\x68' + b'\x00' * 55
    data += b'3dc79f5212e8170acfa9ec95f1d74916542be7b1' + b'\x00' * 24
    data += config.auth_version + bytes([0, len(config.password)])
    for key, value in zip(digest, config.password):
        mixed = key ^ value
        data += bytes([((mixed << 3) & 0xff) | (mixed >> 5)])
    data += b'\x02\x0c'
    data += checksum(data + b'\x01\x26\x07\x11\x00\x00' + mac_field)
    data += b'\x00\x00' + mac_field
    if len(config.password) != 16:
        data += b'\x00' * (len(config.password) // 4)
    return data + b'\x60\xa2' + b'\x00' * 28


class DrcomClient:
    def __init__(self, config, sock):
        self.config = config
        self.sock = sock
        self.host_ip = socket.inet_aton(sock.getsockname()[0])

    def exchange(self, packet, stage, accepts):
        unexpected = False
        for _ in range(self.config.udp_attempts):
            deadline = time.monotonic() + self.config.socket_timeout
            try:
                self.sock.settimeout(self.config.socket_timeout)
                self.sock.send(packet)
                remaining = deadline - time.monotonic()
                while remaining > 0:
                    self.sock.settimeout(remaining)
                    response = self.sock.recv(1024)
                    if accepts(response):
                        return response
                    unexpected = True
                    remaining = deadline - time.monotonic()
            except TimeoutError:
                continue
            except OSError as exc:
                raise DrcomError(f'{stage} UDP 通信失败（{exc}）') from exc
        reason = '收到异常响应' if unexpected else '等待响应超时'
        raise DrcomError(f'{stage} {reason}')

    def login(self):
        challenge = b'\x01\x02' + struct.pack('<H', randrange(0xffff)) + b'\x09' + b'\x00' * 15
        response = self.exchange(
            challenge, 'DrCOM challenge', lambda data: len(data) >= 8 and data[0] == 2
        )
        reported_ip = response[20:24]
        if len(reported_ip) == 4 and reported_ip[0]:
            self.host_ip = reported_ip
        response = self.exchange(
            build_login_packet(self.config, response[4:8], self.host_ip),
            'DrCOM login',
            lambda data: data.startswith(b'\x05') or (len(data) >= 39 and data[0] == 4),
        )
        if response[0] == 5:
            raise DrcomError('DrCOM 登录被拒绝（请检查账号、密码、MAC 和在线状态）')
        log.info('DrCOM 登录成功')

    def heartbeat_packet(self, sequence, tail, packet_type, initial=False):
        version = b'\x0f\x27' if initial else self.config.keep_alive_version
        packet = bytes([7, sequence, 0x28, 0, 0x0b, packet_type]) + version
        packet += b'\x2f\x12' + b'\x00' * 6 + tail + b'\x00' * 4
        if packet_type == 3:
            return packet + b'\x00' * 4 + self.host_ip + b'\x00' * 8
        return packet + b'\x00' * 16

    @staticmethod
    def is_heartbeat_response(data):
        return len(data) >= 20 and data[0] == 7 and data[2:4] == b'\x28\x00'

    def keep_alive(self):
        sequence = 0
        tail = b'\x00' * 4
        for attempt in range(self.config.udp_attempts):
            response = self.exchange(
                self.heartbeat_packet(sequence, tail, 1, initial=attempt == 0),
                'DrCOM 心跳握手',
                lambda data: (self.is_heartbeat_response(data) and data[1] in (0, sequence))
                or (len(data) >= 16 and data[0] == 7 and data[2] == 0x10),
            )
            if response[2] == 0x28:
                break
            sequence = (sequence + 1) % 0xff
        else:
            raise DrcomError('DrCOM 心跳握手未完成')

        online_failures = 0
        next_check = time.monotonic() + self.config.online_check_interval
        while True:
            for offset, packet_type in enumerate((1, 3)):
                response = self.exchange(
                    self.heartbeat_packet(sequence + offset, tail, packet_type),
                    'DrCOM 心跳',
                    self.is_heartbeat_response,
                )
                tail = response[16:20]
            sequence = (sequence + 2) % 0xff
            log.info('DrCOM 心跳正常')

            if (
                self.config.online_check_interval and self.config.online_check_urls
                and time.monotonic() >= next_check
            ):
                if check_real_online(self.config):
                    online_failures = 0
                else:
                    online_failures += 1
                    log.warning('真实联网探测失败（%s/%s）', online_failures, self.config.online_check_fails)
                    if online_failures >= self.config.online_check_fails:
                        raise DrcomError('真实联网探测连续失败')
                next_check = time.monotonic() + self.config.online_check_interval
            time.sleep(self.config.keep_alive_interval)


def run(config):
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(config.socket_timeout)
                sock.bind(('0.0.0.0', PORT))
                sock.connect((config.server, PORT))
                client = DrcomClient(config, sock)
                client.login()
                client.keep_alive()
        except (DrcomError, OSError) as exc:
            log.warning('%s，%s 秒后重试', exc, config.retry_interval)
            time.sleep(config.retry_interval)


def stop(_signum, _frame):
    raise SystemExit(0)


def main():
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stdout
    )
    try:
        config = Config.from_env()
    except ValueError as exc:
        log.error('配置错误：%s', exc)
        return 2

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info('DrCOM 认证服务启动')
    run(config)


if __name__ == '__main__':
    sys.exit(main())
