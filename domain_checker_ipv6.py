#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高性能域名批量查询工具 - IPv6多IP并发版（全局特征码匹配版）
只要WHOIS返回信息中包含以下任何一个英文关键词，就判定为可注册：
- status: free
- status: available
- no match
- no entries found
- not found
- domain not found
- no object found
- not registered
- no data found
- no matching record
- is free
- is available
- no information available
- the queried object does not exist
"""

import os
import sys
import time
import subprocess
import argparse
import random
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# ==================== 配置区域 ====================
TLDS = ['de', 'im', 'pw']        # 要查询的顶级域
CACHE_FILE = 'checked_cache.txt'  # 缓存文件
TIMEOUT_FILE = 'timeout_domains.txt'  # 超时域名汇总文件
MAX_WORKERS = 20                   # 默认并发线程数
MIN_WORKERS = 3                     # 最小并发线程数
BASE_DELAY = 1.0                   # 基础延迟(秒)
MAX_DELAY = 30.0                   # 最大延迟(秒)
REQUEST_TIMEOUT = 15                # WHOIS查询超时(秒)
MAX_RETRIES = 3                     # 每个IP的最大重试次数
MAX_IP_SWITCH = 3                   # 最大IP切换次数

# 自适应限流配置
RATE_LIMIT_THRESHOLD = 3            # 连续限流多少次触发降速
RATE_CHECK_INTERVAL = 10
WORKER_REDUCE_FACTOR = 0.7
DELAY_INCREASE_FACTOR = 1.5

# IPv6 配置
IPV6_PREFIX = None
IPV6_INTERFACE = None
USE_IPV6 = True
# =================================================

# ==================== 全局可注册关键词特征码 ====================
# 只要WHOIS返回信息中包含以下任何一个英文关键词，就判定为可注册
AVAILABLE_KEYWORDS = [
    'status: free',
    'status: available',
    'no match',
    'no entries found',
    'not found',
    'domain not found',
    'no object found',
    'not registered',
    'no data found',
    'no matching record',
    'is free',
    'is available',
    'no information available',
    'the queried object does not exist',
    'no match for',
    'no entries',
    'not found:',
    '%% not found',
    'error:101: no entries found',
    'is available for registration',
]
# =================================================

# 线程锁
file_locks = defaultdict(threading.Lock)
ipv6_lock = threading.Lock()
rate_limit_lock = threading.Lock()
timeout_domains_lock = threading.Lock()

# TLD统计
tld_stats = defaultdict(lambda: {
    'consecutive_timeouts': 0,
    'total_timeouts': 0,
    'current_workers': MAX_WORKERS,
    'current_delay': BASE_DELAY,
    'checked_count': 0,
    'rate_limit_count': 0
})

# 超时域名记录
timeout_domains = defaultdict(list)

# IPv6地址池
ipv6_addresses = []
current_ip_index = 0
max_ip_index = 1000

# 颜色定义
class Colors:
    def __init__(self):
        self.supported = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        self.GREEN = '\033[92m' if self.supported else ''
        self.YELLOW = '\033[93m' if self.supported else ''
        self.RED = '\033[91m' if self.supported else ''
        self.BLUE = '\033[94m' if self.supported else ''
        self.CYAN = '\033[96m' if self.supported else ''
        self.MAGENTA = '\033[95m' if self.supported else ''
        self.BOLD = '\033[1m' if self.supported else ''
        self.RESET = '\033[0m' if self.supported else ''

colors = Colors()

def check_domain_available(output):
    """
    根据全局关键词判断域名是否可注册
    只要WHOIS返回信息中包含任何一个关键词，就返回True
    """
    output_lower = output.lower()
    
    for keyword in AVAILABLE_KEYWORDS:
        if keyword.lower() in output_lower:
            return True
    
    return False

def detect_ipv6_prefix():
    """自动检测本机的IPv6前缀和网卡"""
    global IPV6_PREFIX, IPV6_INTERFACE, ipv6_addresses, max_ip_index
    
    try:
        result = subprocess.run(
            ['ip', '-6', 'addr', 'show'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            print(f"{colors.YELLOW}[警告]{colors.RESET} 无法获取IPv6地址")
            return False
        
        output = result.stdout
        
        pattern = r'inet6\s+([a-f0-9:]+)(?:/\d+)?\s+scope\s+global'
        matches = re.findall(pattern, output, re.IGNORECASE)
        
        if not matches:
            print(f"{colors.YELLOW}[警告]{colors.RESET} 没有找到全局IPv6地址")
            return False
        
        ipv6_addr = matches[0]
        
        if '::' in ipv6_addr:
            prefix_parts = ipv6_addr.split('::')[0]
            parts = prefix_parts.split(':')
            if len(parts) >= 4:
                IPV6_PREFIX = ':'.join(parts[:4])
            else:
                IPV6_PREFIX = prefix_parts
        else:
            parts = ipv6_addr.split(':')
            if len(parts) >= 4:
                IPV6_PREFIX = ':'.join(parts[:4])
            else:
                IPV6_PREFIX = ipv6_addr
        
        route_result = subprocess.run(
            ['ip', '-6', 'route', 'show', 'default'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if route_result.returncode == 0:
            dev_match = re.search(r'dev\s+(\S+)', route_result.stdout)
            if dev_match:
                IPV6_INTERFACE = dev_match.group(1)
            else:
                interface_pattern = r'\d+:\s+(\S+):'
                iface_match = re.search(interface_pattern, output)
                if iface_match:
                    IPV6_INTERFACE = iface_match.group(1)
                else:
                    IPV6_INTERFACE = 'eth0'
        else:
            interface_pattern = r'\d+:\s+(\S+):'
            iface_match = re.search(interface_pattern, output)
            if iface_match:
                IPV6_INTERFACE = iface_match.group(1)
            else:
                IPV6_INTERFACE = 'eth0'
        
        print(f"{colors.GREEN}[IPv6]{colors.RESET} 自动检测到前缀: {IPV6_PREFIX}")
        print(f"{colors.GREEN}[IPv6]{colors.RESET} 自动检测到网卡: {IPV6_INTERFACE}")
        
        # 初始化IPv6地址池
        init_ipv6_pool()
        return True
        
    except Exception as e:
        print(f"{colors.YELLOW}[警告]{colors.RESET} 自动检测IPv6失败: {e}")
        return False

def init_ipv6_pool():
    """初始化IPv6地址池"""
    global ipv6_addresses, max_ip_index
    
    ipv6_addresses = []
    for i in range(max_ip_index):
        ipv6_addr = f"{IPV6_PREFIX}::{i:x}"
        ipv6_addresses.append(ipv6_addr)
    
    print(f"{colors.GREEN}[IPv6]{colors.RESET} 已初始化 {len(ipv6_addresses)} 个IPv6地址到池中")

def get_next_ipv6():
    """获取下一个可用的IPv6地址（循环使用）"""
    global current_ip_index
    
    if not ipv6_addresses:
        return None
    
    with ipv6_lock:
        ipv6_addr = ipv6_addresses[current_ip_index]
        current_ip_index = (current_ip_index + 1) % len(ipv6_addresses)
        return ipv6_addr

def check_ipv6_available():
    """检查IPv6是否可用"""
    if not IPV6_PREFIX:
        return False
    
    try:
        result = subprocess.run(
            ['ping6', '-c', '1', '2001:4860:4860::8888'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

class Counter:
    def __init__(self):
        self.checked = 0
        self.available = 0
        self.timeout_count = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
    
    def add_checked(self):
        with self.lock:
            self.checked += 1
            return self.checked
    
    def add_available(self):
        with self.lock:
            self.available += 1
            return self.available
    
    def add_timeout(self):
        with self.lock:
            self.timeout_count += 1
            return self.timeout_count
    
    def get(self):
        with self.lock:
            return self.checked, self.available, self.timeout_count
    
    def get_speed(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                return self.checked / elapsed
            return 0

counter = Counter()

def check_tld_rate_limit(tld):
    """检测指定TLD的限流情况"""
    with rate_limit_lock:
        stats = tld_stats[tld]
        
        if stats['rate_limit_count'] >= RATE_LIMIT_THRESHOLD:
            old_workers = stats['current_workers']
            old_delay = stats['current_delay']
            
            new_workers = max(int(old_workers * WORKER_REDUCE_FACTOR), MIN_WORKERS)
            new_delay = min(old_delay * DELAY_INCREASE_FACTOR, MAX_DELAY)
            
            stats['current_workers'] = new_workers
            stats['current_delay'] = new_delay
            
            print(f"\n{colors.MAGENTA}{'=' * 60}{colors.RESET}")
            print(f"{colors.BOLD}{colors.YELLOW}[{tld}限流降速]{colors.RESET} 检测到连续 {stats['rate_limit_count']} 次限流")
            print(f"{colors.YELLOW}调整前:{colors.RESET} 并发 {old_workers}, 延迟 {old_delay:.1f}秒")
            print(f"{colors.GREEN}调整后:{colors.RESET} 并发 {new_workers}, 延迟 {new_delay:.1f}秒")
            print(f"{colors.MAGENTA}{'=' * 60}{colors.RESET}\n")
            
            stats['rate_limit_count'] = 0
            return True
        return False

def record_rate_limit(tld):
    """记录一次限流"""
    with rate_limit_lock:
        stats = tld_stats[tld]
        stats['rate_limit_count'] += 1
        stats['consecutive_timeouts'] += 1
        stats['total_timeouts'] += 1
        stats['checked_count'] += 1
        counter.add_timeout()
        
        check_tld_rate_limit(tld)

def record_timeout(tld, domain):
    """记录一次超时（非限流）"""
    with rate_limit_lock:
        stats = tld_stats[tld]
        stats['consecutive_timeouts'] += 1
        stats['total_timeouts'] += 1
        stats['checked_count'] += 1
        counter.add_timeout()
    
    with timeout_domains_lock:
        timeout_domains[tld].append(domain)

def get_tld_config(tld):
    """获取指定TLD的当前配置"""
    with rate_limit_lock:
        stats = tld_stats[tld]
        return stats['current_workers'], stats['current_delay']

def write_timeout_summary(output_files):
    """写入超时总结"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for tld, filename in output_files.items():
        if not os.path.exists(filename):
            continue
            
        with file_locks[filename]:
            try:
                with open(filename, 'a', encoding='utf-8') as f:
                    f.write(f"\n{'=' * 60}\n")
                    f.write(f"查询完成时间: {timestamp}\n")
                    f.write(f"{'=' * 60}\n")
                    
                    tld_timeouts = timeout_domains.get(tld, [])
                    if tld_timeouts:
                        f.write(f"\n以下 {tld} 域名查询超时（换{MAX_IP_SWITCH}个IP仍失败）:\n")
                        f.write(f"{'-' * 40}\n")
                        for domain in sorted(tld_timeouts):
                            f.write(f"{domain}\n")
                        f.write(f"\n总计: {len(tld_timeouts)} 个域名超时\n")
                    else:
                        f.write(f"\n所有 {tld} 域名查询成功，无超时记录\n")
                    
                    f.write(f"{'=' * 60}\n")
            except Exception as e:
                print(f"{colors.RED}[错误]{colors.RESET} 写入超时总结到 {filename} 失败: {e}")
    
    try:
        with open(TIMEOUT_FILE, 'w', encoding='utf-8') as f:
            f.write(f"域名查询超时记录 - {timestamp}\n")
            f.write(f"规则：每个域名最多换{MAX_IP_SWITCH}个IP，每个IP重试{MAX_RETRIES}次\n")
            f.write(f"{'=' * 60}\n\n")
            
            total_timeouts = 0
            for tld, domains in timeout_domains.items():
                if domains:
                    f.write(f"[{tld}] 超时域名 ({len(domains)}个):\n")
                    f.write(f"{'-' * 40}\n")
                    for domain in sorted(domains):
                        f.write(f"{domain}\n")
                    f.write("\n")
                    total_timeouts += len(domains)
            
            if total_timeouts == 0:
                f.write("无超时域名记录\n")
            
            f.write(f"{'=' * 60}\n")
            f.write(f"总计: {total_timeouts} 个域名超时\n")
    except Exception as e:
        print(f"{colors.RED}[错误]{colors.RESET} 写入汇总超时文件失败: {e}")

def load_dictionary(dict_file):
    """加载字典文件"""
    if not os.path.exists(dict_file):
        print(f"{colors.RED}[错误]{colors.RESET} 字典文件 '{dict_file}' 不存在")
        sys.exit(1)
    
    with open(dict_file, 'r', encoding='utf-8') as f:
        prefixes = [line.strip() for line in f 
                   if line.strip() and not line.startswith('#')]
    
    print(f"{colors.CYAN}[信息]{colors.RESET} 已加载 {colors.BOLD}{len(prefixes)}{colors.RESET} 个前缀")
    return prefixes

def load_cache():
    """加载缓存"""
    if not os.path.exists(CACHE_FILE):
        return set()
    
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            cached = set(line.strip() for line in f if line.strip())
        print(f"{colors.YELLOW}[缓存]{colors.RESET} 缓存文件存在: {colors.BOLD}{len(cached)}{colors.RESET} 条记录")
        return cached
    except Exception as e:
        print(f"{colors.YELLOW}[缓存]{colors.RESET} 读取缓存失败: {e}，将创建新缓存")
        return set()

def save_to_cache(domain):
    """保存到缓存"""
    with file_locks['cache']:
        try:
            with open(CACHE_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{domain}\n")
        except Exception as e:
            print(f"{colors.RED}[错误]{colors.RESET} 写入缓存失败: {e}")

def save_available(domain, output_files):
    """保存可用域名"""
    tld = domain.split('.')[-1]
    if tld in output_files:
        output_file = output_files[tld]
        with file_locks[output_file]:
            try:
                with open(output_file, 'a', encoding='utf-8') as f:
                    f.write(f"{domain}\n")
            except Exception as e:
                print(f"{colors.RED}[错误]{colors.RESET} 写入结果文件 {output_file} 失败: {e}")

def check_domain_with_ipv6(domain, source_ip, ip_switch_count=0):
    """
    使用指定IPv6源地址查询域名
    支持IP切换和智能重试
    """
    tld = domain.split('.')[-1]
    workers, delay = get_tld_config(tld)
    
    for attempt in range(MAX_RETRIES):
        try:
            jitter = random.uniform(0.1, 0.5)
            time.sleep(jitter)
            
            result = subprocess.run(
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=REQUEST_TIMEOUT,
                env={'LANG': 'C'}
            )
            
            output = result.stdout
            output_lower = output.lower()
            
            # 检测限流
            limit_indicators = [
                'limit', 'exceeded', 'denied', 'refused', 
                'too many', 'rate limit', 'try again later',
                'error 55000000003',
                'connection refused'
            ]
            
            for indicator in limit_indicators:
                if indicator in output_lower:
                    if attempt < MAX_RETRIES - 1:
                        record_rate_limit(tld)
                        
                        wait_time = delay * (2 ** attempt)
                        wait_time = min(wait_time, MAX_DELAY)
                        
                        print(f"{colors.YELLOW}[{tld}限流]{colors.RESET} {domain} "
                              f"(IP: {source_ip}) 被限流 ({attempt+1}/{MAX_RETRIES})，"
                              f"等待 {wait_time:.1f}秒")
                        time.sleep(wait_time)
                        break
                    else:
                        if ip_switch_count < MAX_IP_SWITCH - 1:
                            new_ip = get_next_ipv6()
                            print(f"{colors.YELLOW}[{tld}IP切换]{colors.RESET} {domain} "
                                  f"当前IP {source_ip} 重试{MAX_RETRIES}次仍限流，"
                                  f"切换到新IP ({ip_switch_count+2}/{MAX_IP_SWITCH})")
                            return check_domain_with_ipv6(domain, new_ip, ip_switch_count + 1)
                        else:
                            print(f"{colors.RED}[{tld}超时]{colors.RESET} {domain} "
                                  f"换{MAX_IP_SWITCH}个IP仍限流，写入超时文件")
                            record_timeout(tld, domain)
                            return False
            
            # 使用全局关键词判断是否可用
            is_available = check_domain_available(output)
            
            return is_available
            
        except subprocess.TimeoutExpired:
            if attempt < MAX_RETRIES - 1:
                workers, delay = get_tld_config(tld)
                wait_time = delay * (2 ** attempt)
                wait_time = min(wait_time, MAX_DELAY)
                print(f"{colors.YELLOW}[{tld}超时]{colors.RESET} {domain} (IP: {source_ip}) "
                      f"查询超时 ({attempt+1}/{MAX_RETRIES})，等待 {wait_time:.1f}秒")
                time.sleep(wait_time)
            else:
                if ip_switch_count < MAX_IP_SWITCH - 1:
                    new_ip = get_next_ipv6()
                    print(f"{colors.YELLOW}[{tld}IP切换]{colors.RESET} {domain} "
                          f"当前IP {source_ip} 重试{MAX_RETRIES}次仍超时，"
                          f"切换到新IP ({ip_switch_count+2}/{MAX_IP_SWITCH})")
                    return check_domain_with_ipv6(domain, new_ip, ip_switch_count + 1)
                else:
                    print(f"{colors.RED}[{tld}超时]{colors.RESET} {domain} "
                          f"换{MAX_IP_SWITCH}个IP仍超时，写入超时文件")
                    record_timeout(tld, domain)
                    return False
                
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                workers, delay = get_tld_config(tld)
                wait_time = delay * (2 ** attempt)
                wait_time = min(wait_time, MAX_DELAY)
                print(f"{colors.YELLOW}[{tld}错误]{colors.RESET} {domain} (IP: {source_ip}) - {str(e)[:50]}，"
                      f"等待 {wait_time:.1f}秒后重试 ({attempt+1}/{MAX_RETRIES})")
                time.sleep(wait_time)
            else:
                if ip_switch_count < MAX_IP_SWITCH - 1:
                    new_ip = get_next_ipv6()
                    print(f"{colors.YELLOW}[{tld}IP切换]{colors.RESET} {domain} "
                          f"当前IP {source_ip} 重试{MAX_RETRIES}次仍错误，"
                          f"切换到新IP ({ip_switch_count+2}/{MAX_IP_SWITCH})")
                    return check_domain_with_ipv6(domain, new_ip, ip_switch_count + 1)
                else:
                    print(f"{colors.RED}[{tld}错误]{colors.RESET} {domain} "
                          f"换{MAX_IP_SWITCH}个IP仍失败，写入超时文件")
                    record_timeout(tld, domain)
                    return False
    
    return False

def worker(domain, output_files):
    """工作线程"""
    tld = domain.split('.')[-1]
    
    source_ip = get_next_ipv6() if USE_IPV6 else "IPv6禁用"
    
    try:
        is_available = check_domain_with_ipv6(domain, source_ip, 0)
    except Exception as e:
        print(f"{colors.RED}[严重错误]{colors.RESET} {domain}: {e}")
        is_available = False
    
    save_to_cache(domain)
    checked = counter.add_checked()
    
    if is_available:
        save_available(domain, output_files)
        available = counter.add_available()
        status = f"{colors.GREEN}可用{colors.RESET}"
    else:
        available = counter.available
        status = f"{colors.RED}不可用{colors.RESET}"
    
    workers, delay = get_tld_config(tld)
    
    if checked % 10 == 0 or is_available:
        speed = counter.get_speed()
        elapsed = time.time() - counter.start_time
        remaining_domains = total_domains - checked
        if speed > 0:
            eta_seconds = remaining_domains / speed
            eta_str = f", ETA: {eta_seconds/60:.1f}分钟"
        else:
            eta_str = ""
        
        _, _, timeouts = counter.get()
        
        ip_info = f"[{source_ip}]" if USE_IPV6 else ""
        
        print(f"{colors.BLUE}[{checked}/{total_domains}]{colors.RESET} "
              f"{colors.MAGENTA}{tld}{colors.RESET}:{domain} {ip_info} - {status} "
              f"(可用: {colors.GREEN}{available}{colors.RESET}"
              f"{colors.CYAN}{eta_str}{colors.RESET}) "
              f"[{tld}并发:{workers} 延迟:{delay:.1f}s 超时:{timeouts}]")

def init_ipv6():
    """初始化IPv6"""
    global USE_IPV6, IPV6_PREFIX, IPV6_INTERFACE
    
    if not USE_IPV6:
        return False
    
    print(f"{colors.CYAN}[IPv6]{colors.RESET} 正在自动检测IPv6配置...")
    
    if not detect_ipv6_prefix():
        print(f"{colors.YELLOW}[警告]{colors.RESET} 自动检测IPv6失败，将使用普通模式")
        USE_IPV6 = False
        return False
    
    if not check_ipv6_available():
        print(f"{colors.YELLOW}[警告]{colors.RESET} IPv6网络可能不可用，将尝试继续")
    
    result = subprocess.run(
        ['ip', '-6', 'addr', 'show', 'dev', IPV6_INTERFACE], 
        capture_output=True, 
        text=True
    )
    
    ipv6_count = result.stdout.count(IPV6_PREFIX)
    print(f"{colors.GREEN}[IPv6]{colors.RESET} 当前接口已有 {ipv6_count} 个IPv6地址")
    
    if ipv6_count == 0:
        print(f"{colors.YELLOW}[警告]{colors.RESET} 没有找到IPv6地址，请先运行 add-ipv6.sh")
        return False
    
    print(f"{colors.GREEN}[IPv6]{colors.RESET} 配置完成，可以使用多IP查询")
    return True

def main():
    global total_domains, max_ip_index, BASE_DELAY, MAX_DELAY, REQUEST_TIMEOUT, MAX_RETRIES, USE_IPV6
    global tld_stats, MIN_WORKERS, RATE_LIMIT_THRESHOLD, MAX_IP_SWITCH
    
    parser = argparse.ArgumentParser(description='高性能域名批量查询工具 - IPv6多IP并发版（全局特征码匹配）')
    parser.add_argument('dictionary', help='字典文件路径 (每行一个前缀)')
    parser.add_argument('--tld', nargs='+', default=TLDS, 
                       help=f'指定TLD，默认: {TLDS}')
    parser.add_argument('--workers', type=int, default=MAX_WORKERS,
                       help=f'初始并发线程数，默认: {MAX_WORKERS}')
    parser.add_argument('--min-workers', type=int, default=MIN_WORKERS,
                       help=f'最小并发线程数，默认: {MIN_WORKERS}')
    parser.add_argument('--delay', type=float, default=BASE_DELAY,
                       help=f'基础延迟(秒)，默认: {BASE_DELAY}')
    parser.add_argument('--max-delay', type=float, default=MAX_DELAY,
                       help=f'最大延迟(秒)，默认: {MAX_DELAY}')
    parser.add_argument('--timeout', type=int, default=REQUEST_TIMEOUT,
                       help=f'查询超时(秒)，默认: {REQUEST_TIMEOUT}')
    parser.add_argument('--retries', type=int, default=MAX_RETRIES,
                       help=f'每个IP最大重试次数，默认: {MAX_RETRIES}')
    parser.add_argument('--max-ips', type=int, default=1000,
                       help=f'最大使用IPv6数量，默认: 1000')
    parser.add_argument('--ip-switch', type=int, default=MAX_IP_SWITCH,
                       help=f'最大IP切换次数，默认: {MAX_IP_SWITCH}')
    parser.add_argument('--threshold', type=int, default=RATE_LIMIT_THRESHOLD,
                       help=f'限流触发阈值，默认: {RATE_LIMIT_THRESHOLD}')
    parser.add_argument('--no-ipv6', action='store_true',
                       help='禁用IPv6多IP功能')
    parser.add_argument('--no-cache', action='store_true',
                       help='不使用缓存')
    parser.add_argument('--no-color', action='store_true',
                       help='强制不使用颜色')
    args = parser.parse_args()
    
    dict_name = os.path.splitext(os.path.basename(args.dictionary))[0]
    tlds = args.tld
    
    output_files = {}
    for tld in tlds:
        output_files[tld] = f"{dict_name}-{tld}可注册.txt"
    
    MIN_WORKERS = args.min_workers
    RATE_LIMIT_THRESHOLD = args.threshold
    max_ip_index = args.max_ips
    BASE_DELAY = args.delay
    MAX_DELAY = args.max_delay
    REQUEST_TIMEOUT = args.timeout
    MAX_RETRIES = args.retries
    MAX_IP_SWITCH = args.ip_switch
    
    for tld in tlds:
        tld_stats[tld]['current_workers'] = args.workers
        tld_stats[tld]['current_delay'] = BASE_DELAY
    
    if args.no_ipv6:
        USE_IPV6 = False
    
    if args.no_color:
        colors.supported = False
        colors.__init__()
    
    max_workers = args.workers
    use_cache = not args.no_cache
    
    separator = f"{colors.BLUE}{'=' * 80}{colors.RESET}"
    print(separator)
    print(f"{colors.BOLD}{colors.CYAN}高性能域名批量查询工具 - IPv6多IP并发版（全局特征码匹配）{colors.RESET}")
    print(f"{colors.YELLOW}字典文件:{colors.RESET} {args.dictionary}")
    print(f"{colors.YELLOW}输出文件:{colors.RESET}")
    for tld, filename in output_files.items():
        print(f"  {colors.MAGENTA}{tld}{colors.RESET}: {filename}")
    print(f"{colors.YELLOW}查询TLD:{colors.RESET} {tlds}")
    print(f"{colors.YELLOW}初始并发:{colors.RESET} {max_workers} (每个TLD独立)")
    print(f"{colors.YELLOW}最小并发:{colors.RESET} {MIN_WORKERS}")
    print(f"{colors.YELLOW}限流阈值:{colors.RESET} {RATE_LIMIT_THRESHOLD}次连续限流")
    print(f"{colors.YELLOW}最大IPv6数:{colors.RESET} {max_ip_index}")
    print(f"{colors.YELLOW}每个IP重试:{colors.RESET} {MAX_RETRIES}次")
    print(f"{colors.YELLOW}最大IP切换:{colors.RESET} {MAX_IP_SWITCH}次")
    print(f"{colors.YELLOW}基础延迟:{colors.RESET} {BASE_DELAY}秒 (每个TLD独立)")
    print(f"{colors.YELLOW}最大延迟:{colors.RESET} {MAX_DELAY}秒")
    print(f"{colors.YELLOW}查询超时:{colors.RESET} {REQUEST_TIMEOUT}秒")
    print(f"{colors.YELLOW}使用缓存:{colors.RESET} {use_cache}")
    print(separator)
    
    if USE_IPV6:
        USE_IPV6 = init_ipv6()
    
    prefixes = load_dictionary(args.dictionary)
    cached = load_cache() if use_cache else set()
    
    all_domains = []
    for prefix in prefixes:
        for tld in tlds:
            domain = f"{prefix}.{tld}".lower()
            if use_cache and domain in cached:
                continue
            all_domains.append(domain)
    
    total_domains = len(all_domains)
    print(f"\n{colors.CYAN}本次需查询 {colors.BOLD}{total_domains}{colors.RESET}{colors.CYAN} 个域名{colors.RESET}")
    
    if total_domains == 0:
        print(f"{colors.YELLOW}[提示]{colors.RESET} 所有域名都已缓存，无需查询")
        return
    
    print(f"{colors.CYAN}启动 {max_workers} 个线程并发查询...{colors.RESET}\n")
    start_time = time.time()
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(worker, domain, output_files) for domain in all_domains]
            for future in as_completed(futures):
                future.result()
    
    except KeyboardInterrupt:
        print(f"\n\n{colors.RED}[警告]{colors.RESET} 用户中断，正在等待当前任务完成...")
    
    finally:
        total_time = time.time() - start_time
        checked, available, timeouts = counter.get()
        speed = checked / total_time if total_time > 0 else 0
        
        write_timeout_summary(output_files)
        
        print("\n" + separator)
        print(f"{colors.BOLD}{colors.GREEN}查询完成{colors.RESET}")
        print(f"{colors.CYAN}总共检查:{colors.RESET} {colors.BOLD}{checked}{colors.RESET} 个域名")
        print(f"{colors.CYAN}发现可用:{colors.RESET} {colors.BOLD}{colors.GREEN}{available}{colors.RESET} 个域名")
        print(f"{colors.CYAN}超时/限流:{colors.RESET} {colors.BOLD}{timeouts}{colors.RESET} 次")
        print(f"{colors.CYAN}最终各TLD配置:{colors.RESET}")
        for tld in tlds:
            workers, delay = get_tld_config(tld)
            tld_timeout_count = len(timeout_domains.get(tld, []))
            timeout_color = colors.RED if tld_timeout_count > 0 else colors.GREEN
            print(f"  {colors.MAGENTA}{tld}{colors.RESET}: 并发 {workers}, 延迟 {delay:.1f}秒, "
                  f"超时 {timeout_color}{tld_timeout_count}{colors.RESET}个")
        print(f"{colors.CYAN}总耗时:{colors.RESET} {colors.BOLD}{total_time/60:.1f}{colors.RESET} 分钟")
        print(f"{colors.CYAN}平均速度:{colors.RESET} {colors.BOLD}{speed:.2f}{colors.RESET} 个/秒")
        print(f"{colors.CYAN}可用域名已保存到以下文件:{colors.RESET}")
        for tld, filename in output_files.items():
            tld_timeout_count = len(timeout_domains.get(tld, []))
            timeout_info = f" (含{tld_timeout_count}个超时记录)" if tld_timeout_count > 0 else ""
            print(f"  {colors.MAGENTA}{tld}{colors.RESET}: {filename}{timeout_info}")
        print(f"{colors.CYAN}超时汇总文件:{colors.RESET} {TIMEOUT_FILE}")
        print(f"{colors.CYAN}缓存文件:{colors.RESET} {CACHE_FILE}")
        print(separator)

if __name__ == "__main__":
    main()
