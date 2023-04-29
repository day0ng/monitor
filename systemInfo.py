#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@name: 系统信息 / system_info
@author: PurePeace, Dayong Wang
depends: WMI, cachelib, psutil

'''

import argparse
import hashlib
import json
import logging
import os
import psutil
import platform
import re
import sys
import time
from typing import List, Dict, Any
from cachelib import SimpleCache
cache = SimpleCache()
UNIX: bool = psutil.POSIX
MACOS: bool = psutil.MACOS
VER: str = '0.9.2.3 (2022/10/15)'
UNKNOWN_OS: str = '未知系统版本.'


# ---- Email Module - Begin ----

import smtplib
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import quote


def send_email(smtp_host, smtp_port, mail_from, mail_password, mail_to, subject='No Subject', content=''):

    if smtp_host == None or len(smtp_host) == 0:
        logging.warning(" Invalid SMTP host (smtp_host)")
        return

    if smtp_port == None or len(smtp_port) == 0:
        logging.warning(" Invalid SMTP port (smtp_port)")
        return

    if mail_from == None or len(mail_from) == 0:
        logging.warning(" Invalid Email username (mail_from)")
        return

    if mail_password == None or len(mail_password) == 0:
        logging.warning(" Invalid Email password (mail_password)")
        return

    if mail_to == None or len(mail_to) == 0:
        logging.warning(" Invalid Email address (mail_to)")
 
    email = MIMEMultipart()
    email['Subject'] = subject
    email['From'] = mail_from
    email['To'] = mail_to
    email.attach(MIMEText(content, 'plain', 'utf-8'))

    smtp = smtplib.SMTP_SSL(smtp_host, smtp_port)

    try:
        smtp.login(mail_from, mail_password)
    except Exception as err:
        print(err)
        sys.exit()

    try:
        smtp.sendmail(mail_from, mail_to, email.as_string())
    except Exception as err:
        print(err)
        sys.exit()

# ---- Email Module - End ----
 


# The beginning of Class CpuConstants
class CpuConstants:

    def __init__(self):

        self.WMI = None
        self.initialed: bool = False
        self.cpu_list: list = []         # Windows only

        self.cpu_count: int = 0          # 物理cpu数量
        self.cpu_core: int = 0           # cpu物理核心数
        self.cpu_threads: int = 0        # cpu逻辑核心数
        self.cpu_name: str = ''          # cpu型号

        self.update(True)


    def update(self, update: bool = False) -> None:

        if UNIX or MACOS:
            self.get_cpu_constants_unix(update)
        else:
            self.get_cpu_constants_windows(update)
        self.initialed = True


    @property
    def get_dict(self) -> Dict[int, str]:

        if not self.initialed: self.update()
        return {
            'cpu_count': self.cpu_count,
            'cpu_name': self.cpu_name,
            'cpu_core': self.cpu_core,
            'cpu_threads': self.cpu_threads
        }


    def get_cpu_constants_unix(self, update: bool = False) -> None:

        if update or not self.initialed:
            ids: list = re.findall("physical id.+", readfile('/proc/cpuinfo'))

            # 物理cpu个数
            self.cpu_count = len(set(ids))

            # cpu型号（名称）
            self.cpu_name = self.get_cpu_type_unix()

            self.get_cpu_constants_both()


    def init_wmi(self) -> None:

        import wmi
        self.WMI = wmi.WMI()


    def get_cpu_constants_both(self, update: bool = False) -> None:

        if update or not self.initialed:

            # cpu逻辑核心数
            self.cpu_threads = psutil.cpu_count()

            # cpu物理核心数
            self.cpu_core = psutil.cpu_count(logical=False)


    def get_cpu_constants_windows(self, update: bool = False) -> None:

        if update or not self.initialed:

            # 初始化wmi
            if self.WMI == None: self.init_wmi()

            # cpu列表
            self.cpu_list = self.WMI.Win32_Processor()

            # 物理cpu个数
            self.cpu_count = len(self.cpu_list)

            # cpu型号（名称）
            self.cpu_name = self.cpu_list[0].Name

            self.get_cpu_constants_both()


    @staticmethod
    def get_cpu_type_unix() -> str:

        cpuinfo: str = readfile('/proc/cpuinfo')
        rep: str = 'model\s+name\s+:\s+(.+)'
        cpu_type: str = ''

        tmp = re.search(rep,cpuinfo,re.I)
        if tmp:
            cpu_type = tmp.groups()[0]
        else:
            cpuinfo = exec_shell_unix('LANG="en_US.UTF-8" && lscpu')[0]
            rep = 'Model\s+name:\s+(.+)'
            tmp = re.search(rep,cpuinfo,re.I)
            if tmp:
                cpu_type = tmp.groups()[0]

        return cpu_type

# The ending of Class CpuConstants



def sys_time(time_format = '%Y-%m-%d %H:%M:%S'):
    return time.strftime(time_format, time.localtime(time.time()))


def secs2hours(secs):
    mm, ss = divmod(secs, 60)
    hh, mm = divmod(mm, 60)
    return "%d:%0.2d:%02d" % (hh, mm, ss)


def readfile(filename: str) -> str:
    try:
        with open(filename, 'r', encoding='utf-8') as file: return file.read()
    except Exception:
        pass
    return ''


def byte_trans_unit(byte: int, target: str):
    return round(float(byte/1024**(('KB','MB','GB','TB').index(target) + 1)), 2)


def get_cpu_constants() -> dict:
    return cpuConstants.get_dict


def md5(strings: str) -> str:
    m = hashlib.md5()
    m.update(strings.encode('utf-8'))
    return m.hexdigest()


def exec_shell_unix(cmdstring: str, shell=True):
    import subprocess, tempfile
    a: str = ''
    e: str = ''

    try:
        rx: str = md5(cmdstring)
        succ_f = tempfile.SpooledTemporaryFile(
            max_size = 4096,
            mode = 'wb+',
            suffix = '_succ',
            prefix = 'btex_' + rx
        )
        err_f = tempfile.SpooledTemporaryFile(
            max_size = 4096,
            mode = 'wb+',
            suffix = '_err',
            prefix = 'btex_' + rx
        )
        sub = subprocess.Popen(
            cmdstring,
            close_fds = True,
            shell = shell,
            bufsize = 128,
            stdout = succ_f,
            stderr = err_f
        )
        sub.wait()
        err_f.seek(0)
        succ_f.seek(0)
        a = succ_f.read()
        e = err_f.read()
        if not err_f.closed: err_f.close()
        if not succ_f.closed: succ_f.close()
    except Exception as err:
        print(err)

    try:
        if type(a) == bytes: a = a.decode('utf-8')
        if type(e) == bytes: e = e.decode('utf-8')
    except Exception as err:
        print(err)

    return a,e


def get_battery():
    battery = psutil.sensors_battery()
    if battery:
        plugged = battery.power_plugged
        if plugged:
            return dict({'charge': "%s%%" % (battery.percent), 'time_left': 'power_plugged'})
        else:
            return dict({'charge': "%s%%" % (battery.percent), 'time_left': secs2hours(battery.secsleft)})
    else:
        return dict({'battery': 'n/a'})


def get_battery_lite():
    return get_battery()


def get_cpu(interval: int = 1) -> Dict[str, Any]:
    time.sleep(0.1)
    # cpu总使用率
    total: float = psutil.cpu_percent(interval)
    # 每个逻辑cpu（线程）的使用率
    threads: List[float] = psutil.cpu_percent(percpu=True)
    return {
        'total_usage': total,
        'threads_usage': threads,
        **cpuConstants.get_dict
        }


def get_cpu_lite(dict_cpu):
    return dict({'total_usage': dict_cpu['total_usage']})


def get_disk() -> dict:
    try:
        if UNIX:
            return get_disk_unix()
        else:
            return get_disk_windows()
    except Exception as err:
        print('获取磁盘信息异常（UNIX = {}）：'.format(UNIX), err)
        return {}


def get_disk_lite(dict_disk) -> dict:
    tmp_dict = dict()
    for tmp_mnt in list(dict_disk):
        if UNIX:
            tmp_dict.update({
                tmp_mnt: {
                    'size': dict_disk[tmp_mnt]['size'], 
                    'usage': dict_disk[tmp_mnt]['usage']
                    }
                })
        else:
            tmp_dict.update({
                tmp_mnt: {
                    'total': dict_disk[tmp_mnt]['total'], 
                    'usage': dict_disk[tmp_mnt]['usage']
                    }
                })
    return tmp_dict


def get_disk_windows() -> dict:
    disk_part: list = psutil.disk_partitions()
    disk_info: dict = {}
    for disk in disk_part:
        try:
            mount_point = psutil.disk_usage(disk.mountpoint)
        except Exception as err:
            if err.winerror == 21: continue
        dev = re.sub(":.*$", '', disk.device)
        disk_info[dev] = {
            'unit': 'GB',
            'total': byte_trans_unit(mount_point.total, 'GB'),
            'used': byte_trans_unit(mount_point.used, 'GB'),
            'free': byte_trans_unit(mount_point.free, 'GB'),
            'usage': mount_point.percent,
            'fstype': disk.fstype
        }
    return disk_info


def get_disk_unix() -> dict:
    str_mount: str = (exec_shell_unix("df -h -P |grep '/' |grep -v tmpfs |awk '{printf(\"%s,%s,%s,%s,%s\\n\",$6,$2,$3,$4,$5)}'")[0]).strip()
    list_mount: list = str_mount.split('\n')
    black_list: list = [
        '/mnt/cdrom',
        '/boot',
        '/boot/efi',
        '/dev',
        '/dev/shm',
        '/run/lock',
        '/run',
        '/run/shm',
        '/run/user'
    ]

    dict_mount = dict()
    for tmp_row in list_mount:
        row = tmp_row.split(',')
        if row[0] in black_list: continue
        dict_mount.update(dict({row[0]: {'size': row[1], 'used':row[2], 'avail':row[3], 'usage':row[4]}}))

    return dict_mount


def get_error() -> dict:
    import traceback
    error_msg = traceback.format_exc().strip()
    if error_msg == 'NoneType: None':
        error_msg = ''
    return {'error': error_msg}


def get_error_lite():
    return get_error()


def get_inodes() -> dict:
    if UNIX: return get_inodes_unix()
    else: return dict()


def get_inodes_lite(dict_inodes):
    tmp_dict = dict()
    for tmp in list(dict_inodes):
        if UNIX:
            tmp_dict.update({
                tmp: {
                    'inodes': dict_inodes[tmp]['inodes'], 
                    'usage': dict_inodes[tmp]['usage']
                    }
                })
    return tmp_dict


def get_inodes_unix() -> dict:
    str_inodes: str = (exec_shell_unix("df -i -P |grep '/' |grep -v tmpfs |awk '{printf(\"%s,%s,%s,%s,%s\\n\",$6,$2,$3,$4,$5)}'")[0]).strip()
    list_inodes: list = str_inodes.split('\n')
    dict_inodes = dict()
    for tmp_row in list_inodes:
        row = tmp_row.split(',')
        dict_inodes.update(dict({row[0]: {'inodes': row[1], 'used':row[2], 'free':row[3], 'usage':row[4]}}))
    return dict_inodes


def get_io():
    return get_io_read_write()


def get_io_lite(dict_io):
    return dict_io


def get_io_read_write() -> Dict[str, int]:
    io_disk = psutil.disk_io_counters()
    io_total = dict()
    io_total['write'] = get_io_write(io_disk.write_bytes)
    io_total['read'] = get_io_read(io_disk.read_bytes)
    return io_total


def get_io_write(io_write: int) -> int:
    disk_write: int = 0
    old_write: int = cache.get('io_write')
    if not old_write:
        cache.set('io_write', io_write)
        return disk_write;
    old_time: float = cache.get('io_time')
    new_time: float = time.time()
    if not old_time: old_time = new_time
    io_end: int = (io_write - old_write)
    time_end: float = (time.time() - old_time)
    if io_end > 0:
        if time_end < 1: time_end = 1
        disk_write = io_end / time_end
    cache.set('io_write',io_write)
    cache.set('io_time',new_time)
    if disk_write > 0: return int(disk_write)
    return 0


def get_io_read(io_read):
    disk_read: int = 0
    old_read: int = cache.get('io_read')
    if not old_read:
        cache.set('io_read',io_read)
        return disk_read;
    old_time: float = cache.get('io_time')
    new_time: float = time.time()
    if not old_time: old_time = new_time
    io_end: int = (io_read - old_read)
    time_end: float = (time.time() - old_time)
    if io_end > 0:
        if time_end < 1: time_end = 1;
        disk_read = io_end / time_end;
    cache.set('io_read', io_read)
    if disk_read > 0: return int(disk_read)
    return 0


def get_load():
    return get_load_average()


def get_load_lite(dict_load):
    return dict_load


def get_load_average() -> dict:
    if hasattr(os, 'getloadavg'):
        c = os.getloadavg()
    else:
        c = [0,0,0]
    data = dict()
    for idx, i in enumerate(('1-min', '5-min', '15-min')):
        data[i] = round(c[idx], 2)
    return data


def get_mem() -> dict:
    if MACOS: 
        return get_mem_macos()
    elif UNIX:
        return get_mem_unix()
    else:
        return get_mem_windows()


def get_mem_lite(dict_mem):
    return dict({'total': dict_mem['total'], 'usage': dict_mem['usage']})


def get_mem_unix() -> Dict[str, int]:
    mem = psutil.virtual_memory()
    mem_info: dict = {
        'unit': 'GB',
        'total': byte_trans_unit(mem.total, 'GB'),
        'free': byte_trans_unit(mem.free, 'GB'),
        'buffers': byte_trans_unit(mem.buffers, 'GB'),
        'cached': byte_trans_unit(mem.cached, 'GB')
    }
    mem_info['used'] = mem_info['total'] - mem_info['free'] - mem_info['buffers'] - mem_info['cached']
    mem_info['usage'] = round(100 * mem_info['used'] / mem_info['total'], 2)
    return mem_info


def get_mem_macos() -> Dict[str, int]:
    mem = psutil.virtual_memory()
    mem_info: dict = {
        'unit': 'GB',
        'total': byte_trans_unit(mem.total, 'GB'),
        'available': byte_trans_unit(mem.available, 'GB'),
        'usage': mem.percent
    }
    mem_info['used'] = mem_info['total'] - mem_info['available']
    return mem_info


def get_mem_windows() -> dict:
    mem = psutil.virtual_memory()
    mem_info: dict = {
        'unit': 'GB',
        'total': byte_trans_unit(mem.total, 'GB'),
        'free': byte_trans_unit(mem.free, 'GB'),
        'used': byte_trans_unit(mem.used, 'GB'),
        'usage': round(100 * mem.used / mem.total, 2)
    }
    return mem_info


def get_network_lite():
    return get_network()


def get_network() -> dict:
    network_io: list = [0,0,0,0]
    cache_timeout: int = 86400
    try:
        network_io = psutil.net_io_counters()[:4]
    except Exception:
        pass
    otime = cache.get("otime")
    if not otime:
        otime = time.time()
        cache.set('up',network_io[0],cache_timeout)
        cache.set('down',network_io[1],cache_timeout)
        cache.set('otime',otime ,cache_timeout)
    ntime = time.time()
    network_info = dict()
    network_info['up'] = 0
    network_info['down'] = 0
    network_info['upTotal']   = network_io[0]
    network_info['downTotal'] = network_io[1]
    try:
        network_info['up'] = round(
            float(network_io[0] - cache.get("up")) / 1024 / (ntime - otime),
            2
        )
        network_info['down'] = round(
            float(network_io[1] - cache.get("down")) / 1024 / (ntime -  otime),
            2
        )
    except Exception:
        pass
    network_info['downPackets'] = network_io[3]
    network_info['upPackets'] = network_io[2]
    cache.set('up',network_io[0],cache_timeout)
    cache.set('down',network_io[1],cache_timeout)
    cache.set('otime', time.time(),cache_timeout)
    return network_info


def get_os_version() -> str:
    if MACOS:
        return get_os_version_macos()
    elif UNIX:
        return get_os_version_unix()
    else:
        return get_os_version_windows()


def get_os_version_lite():
    return get_os_version()


def get_reg_value(key: str, subkey: str, value: str) -> Any:
    import winreg
    key = getattr(winreg, key)
    handle = winreg.OpenKey(key, subkey)
    (value, type) = winreg.QueryValueEx(handle, value)
    return value


def get_os_version_windows() -> str:
    try:
        import platform
        bit: str = 'x86';
        if 'PROGRAMFILES(X86)' in os.environ: bit = 'x64'
        def get(key: str):
            return get_reg_value(
                "HKEY_LOCAL_MACHINE",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                key
            )
        os_name = get('ProductName')
        build = get('CurrentBuildNumber')
        version: str = '{} (build {}) {} (Py{})'.format(
            os_name, build, bit, platform.python_version())
        return version
    except Exception as err:
        print('获取系统版本失败，错误：' + str(err))
        return UNKNOWN_OS


def get_os_version_unix() -> str:
    try:
        version: str = readfile('/etc/redhat-release')
        if not version:
            version = readfile(
                '/etc/issue'
            ).strip().split("\n")[0].replace('\\n','').replace('\l','').strip()
        else:
            version = version.replace(
                'release ',''
            ).replace('Linux','').replace('(Core)','').strip()
        v = sys.version_info
        return version + ' (Py {}.{}.{})'.format(v.major, v.minor, v.micro)
    except Exception as err:
        print('获取系统版本失败，错误：', err)
        return UNKNOWN_OS



def get_os_version_macos() -> str:
    try:
        version: str = exec_shell_unix('sw_vers')[0].strip()
        if version:
            version = re.sub("[\s]", ",", version)
            version = re.sub("[a-zA-Z:]+:,", '', version)
            version = version.replace(",", " ")
            v = sys.version_info
            return version + ' (Py {}.{}.{})'.format(v.major, v.minor, v.micro)
    except Exception:
        version = UNKNOWN_OS
    return version


def get_service(service_name):
    if UNIX:
        return get_service_unix()
    else:
        return get_service_win(service_name)


def get_service_unix():
    return dict({'Warning': 'the function is not ready yet'})


def get_service_win(service_name):
    # 这个service_name是psutil.display_name()，也就是在 services.msc 中看到的服务名称    
    name = 'n/a'
    status = 'n/a'
    dict_service = dict()
    service_name = service_name.strip().lower()   
    if service_name == 'all':
        ss = list(psutil.win_service_iter())
        for s in ss:
            name = s.name()
            dname = s.display_name()
            status = s.status()
            dict_service.update({name: {'diaplay_name': dname, 'status': status}})
    else:
        for name in service_name.split(';'):
            if name == '' or len(name) == 0: continue
            try:
                s = psutil.win_service_get(name)
                dname = s.display_name()
                status = s.status()
            except Exception:
                dname = 'n/a'
                status = 'n/a'
            dict_service.update({name: {'display_name': dname, 'status': status}})
    return dict_service


def get_uptime() -> str:
    if MACOS:
        str_up = exec_shell_unix("uptime")[0].strip('\n')
        str_up = re.sub("days, *", "days ", str_up)
        str_up = re.sub("^.*up ", "", str_up)
        str_up = re.sub(",.*$", "", str_up)
        return str_up
    elif UNIX:
        return exec_shell_unix("uptime -p")[0].strip('\n')
    else:
        uptime = time.time() - psutil.boot_time()
        return "%0.2f hours" % (uptime / (60*60))


def get_uptime_lite():
    return get_uptime()


def get_system_info() -> dict:
    system_info = dict()
    system_info['battery'] = get_battery()
    system_info['cpu'] = get_cpu()
    system_info['disk'] = get_disk()
    system_info['load'] = get_load_average()
    system_info['mem'] = get_mem()
    system_info['network'] = get_network()
    system_info['os'] = get_os_version()
    system_info['uptime'] = get_uptime()
    return system_info


if __name__ == '__main__':

    p = argparse.ArgumentParser(
            formatter_class=argparse.RawTextHelpFormatter,
            description='''
  This is realtime system monitoring program, and it could be run at Windows,
  Linux and MacOS. 
''')

    p.add_argument('--all', '-a',       action='store_true', help='all system information')
    p.add_argument('--battery',         action='store_true', help='battery information')
    p.add_argument('--cpu',             action='store_true', help='CPU information')
    p.add_argument('--disk',            action='store_true', help='disk information')
    p.add_argument('--error',           action='store_true', help='errors log')
    p.add_argument('--hostname',        type=str, default='NONAME', help='set hostname')
    p.add_argument('--inode',           action='store_true', help='inodes information (unix only)')
    p.add_argument('--io',              action='store_true', help='IO read and write information')
    p.add_argument('--json',            action='store_true', help='JSON output')
    p.add_argument('--load',            action='store_true', help='system load information')
    p.add_argument('--mail_from',       type=str, default='', help='username for SMTP authentication')
    p.add_argument('--mail_password',   type=str, default='', help='password for SMTP authentication')
    p.add_argument('--mail_to',         type=str, default='', help='email addresses to recieve the infomation')
    p.add_argument('--memory',          action='store_true', help='memory information')
    p.add_argument('--network',         action='store_true', help='network information')
    p.add_argument('--os',              action='store_true', help='OS information')
    p.add_argument('--service',         type=str, default='', help='servcie information')
    p.add_argument('--smtp_host',       type=str, default='', help='hostname of SMTP server')
    p.add_argument('--smtp_port',       type=str, default='', help='port number of SMTP server')
    p.add_argument('--uptime',          action='store_true', help='system uptime')
    p.add_argument('--verbose', '-v',   action='store_true', help='verbose output')
    p.add_argument('--version', '-V',   action='store_true', help='version number of this program')
    args = p.parse_args()

    cpuConstants = CpuConstants()
    json_output = False
    verbose_output = False
    output = dict({'hostname': '', 'datetime': sys_time()})
    output_lite = output.copy()
    output_text = ''
    smtp_host = ''
    smtp_port = ''
    mail_from = ''
    mail_password = ''
    mail_to   = ''


    if args.all:
        output.update(get_system_info())
        # 当--all时，默认输出为verbose，因此output_lite直接copy
        output_lite = output.copy()

    if args.battery:
        output['battery'] = get_battery()
        output_lite['battery'] = get_battery()

    if args.cpu:
        output['cpu'] = get_cpu()
        output_lite['cpu'] = get_cpu_lite(output['cpu'])

    if args.disk:
        output['disk'] = get_disk()
        output_lite['disk'] = get_disk_lite(output['disk'])

    if args.error:
        output['error'] = get_error()
        output_lite['error'] = get_error_lite()

    if args.hostname:
        hostname = args.hostname.strip()
        output['hostname'] = hostname
        output_lite['hostname'] = hostname

    if args.inode:
        output['inode'] = get_inodes()
        output_lite['inode'] = get_inodes_lite(output['inode'])

    if args.io:
        output['io'] = get_io()
        output_lite['io'] = get_io_lite(output['io'])

    if args.json:
        json_output = True

    if args.load:
        output['load'] = get_load()
        output_lite['load'] = get_load_lite(output['load'])

    if args.memory:
        output['memory'] = get_mem()
        output_lite['memory'] = get_mem_lite(output['memory'])

    if args.network:
        output['network'] = get_network()
        output_lite['network'] = get_network_lite()
        
    if args.os:
        output['os'] = get_os_version()
        output_lite['os'] = get_os_version_lite()

    if args.service:
        service_name = args.service.strip()
        output['service'] = get_service(service_name)
        output_lite['service'] = get_service(service_name)
        
    if args.uptime:
        output['uptime'] = get_uptime()
        output_lite['uptime'] = get_uptime_lite()

    if args.verbose:
        verbose_output = True

    if args.version:
        output['version'] = VER
        output_lite['version'] = VER

    # Email
    if args.smtp_host:
        smtp_host = args.smtp_host.strip().lower()
        if re.search("^([a-z_0-9]+\.)+[a-z_0-9]+$", smtp_host) == None:
            logging.warning(' Wrong SMTP host (%s), it should be a domain name' % (smtp_host))
            smtp_host = ''
            sys.exit()

    if args.smtp_port:
        smtp_port = args.smtp_port.strip().lower()
        if not smtp_port.isdigit():
            logging.warning(' SMTP port should be integer (%s)' % (smtp_port))
            smtp_port = ''
            sys.exit()

    if args.mail_from:
        mail_from = args.mail_from.strip().lower()
        if re.search("[a-z_0-9]+@[a-z_0-9]+\.[a-z]+[\.a-z;]*", mail_from) == None:
            logging.warning(' Wrong Email address (%s)' % (mail_from))
            mail_from = ''
            sys.exit()

    if args.mail_password:
        mail_password = args.mail_password.strip()

    if args.mail_to:
        mail_to = args.mail_to.strip().lower()
        if re.search("[a-z_0-9]+@[a-z_0-9]+\.[a-z]+[\.a-z;]*", mail_to) == None:
            logging.warning(' Wrong Email address (%s)' % (mail_to))
            mail_to = ''
            sys.exit()

    # No arguments assigned
    if not args.mail_to and len(output) <= 2:
        p.print_help()
        print('')
        sys.exit()

    # JSON
    if json_output:
        output_json      = json.dumps(output, ensure_ascii=False)
        output_lite_json = json.dumps(output_lite, ensure_ascii=False)
        if verbose_output: 
            output_text = output_json
        else:
            output_text = output_lite_json
        print(output_text)

    # Non-JSON
    else:
        if verbose_output: 
            for key in list(output):
                output_text = "%s\n%s = %s" % (output_text, key, output[key])
        else:
            for key in list(output_lite):
                output_text = "%s\n%s = %s" % (output_text, key, output_lite[key])
        print(output_text.strip())

    # Send mail
    if mail_to != None and len(mail_to) > 0:           
        send_email(smtp_host, smtp_port, mail_from, mail_password, mail_to, hostname, output_text.strip())
        logging.info("%s: Mail to %s was sent successfully." % (hostname, mail_to))

    # This is the end
    sys.exit()


