#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高性能域名批量查询工具 - IPv6多IP并发版（自适应限流版）
为每个线程分配不同的IPv6源地址，突破限流
自动检测本机IPv6前缀，无需手动配置
输出文件名自动根据字典名和TLD生成：字典名-TLD可注册.txt
内存占用: ~50-80MB (取决于并发数)
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

# ==================== 配置区域 ====================
TLDS = ['de', 'im', 'pw']        # 要查询的顶级域
CACHE_FILE = 'checked_cache.txt'  # 缓存文件
# OUTPUT_FILE 将在 main 中根据字典名和TLD动态生成
MAX_WORKERS = 20                   # 默认并发线程数
MIN_WORKERS = 3                     # 最小并发线程数（限流时降低到多少）
BASE_DELAY = 1.0                   # 基础延迟(秒)
MAX_DELAY = 30.0                   # 最大延迟(秒，被限流时自动增加)
REQUEST_TIMEOUT = 15                # WHOIS查询超时(秒)
MAX_RETRIES = 3                     # 最大重试次数

# 自适应限流配置
RATE_LIMIT_THRESHOLD = 10           # 连续超时/限流多少次触发降速
RATE_CHECK_INTERVAL = 50            # 每检查多少个域名检测一次限流情况
WORKER_REDUCE_FACTOR = 0.7          # 并发数降低系数 (降低30%)
DELAY_INCREASE_FACTOR = 1.5         # 延迟增加系数 (增加50%)

# IPv6 配置（将自动检测，无需手动设置）
IPV6_PREFIX = None                  # 将在 init_ipv6() 中自动检测
IPV6_INTERFACE = None                # 将在 init_ipv6() 中自动检测
USE_IPV6 = True                     # 是否使用IPv6
# =================================================

# 线程锁，用于保护文件写入
file_lock = threading.Lock()
# IPv6地址池锁
ipv6_lock = threading.Lock()
# 自适应限流相关锁和变量
rate_limit_lock = threading.Lock()
consecutive_timeouts = 0
total_timeouts = 0
current_workers = MAX_WORKERS
current_delay = BASE_DELAY

# 当前已分配的IPv6索引
current_ip_index = 0
max_ip_index = 1000  # 最多使用1000个不同IP（可以根据需要调整）

# 颜色定义 - 自动检测终端支持
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

def detect_ipv6_prefix():
    """自动检测本机的IPv6前缀和网卡"""
    global IPV6_PREFIX, IPV6_INTERFACE
    
    try:
        # 获取所有IPv6地址
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
        
        # 查找全局IPv6地址（不是fe80开头的本地链路地址）
        # 匹配模式：inet6 2001:db8:1234:5678::1/64 scope global
        pattern = r'inet6\s+([a-f0-9:]+)(?:/\d+)?\s+scope\s+global'
        matches = re.findall(pattern, output, re.IGNORECASE)
        
        if not matches:
            print(f"{colors.YELLOW}[警告]{colors.RESET} 没有找到全局IPv6地址")
            return False
        
        # 使用第一个全局IPv6地址
        ipv6_addr = matches[0]
        
        # 提取前缀（去掉最后的::1或类似部分）
        # 如果是 2a01:4f9:6b:1234::1 这种格式
        if '::' in ipv6_addr:
            prefix_parts = ipv6_addr.split('::')[0]
            # 确保是64位前缀（通常前4段）
            parts = prefix_parts.split(':')
            if len(parts) >= 4:
                IPV6_PREFIX = ':'.join(parts[:4])
            else:
                IPV6_PREFIX = prefix_parts
        else:
            # 如果是完整地址，取前4段
            parts = ipv6_addr.split(':')
            if len(parts) >= 4:
                IPV6_PREFIX = ':'.join(parts[:4])
            else:
                IPV6_PREFIX = ipv6_addr
        
        # 获取默认网卡
        # 查找有默认路由的网卡
        route_result = subprocess.run(
            ['ip', '-6', 'route', 'show', 'default'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if route_result.returncode == 0:
            # 匹配 dev eth0 这种格式
            dev_match = re.search(r'dev\s+(\S+)', route_result.stdout)
            if dev_match:
                IPV6_INTERFACE = dev_match.group(1)
            else:
                # 如果没有默认路由，用第一个有IPv6的网卡
                interface_pattern = r'\d+:\s+(\S+):'
                iface_match = re.search(interface_pattern, output)
                if iface_match:
                    IPV6_INTERFACE = iface_match.group(1)
                else:
                    IPV6_INTERFACE = 'eth0'  # 默认
        else:
            # 如果没有默认路由，用第一个有IPv6的网卡
            interface_pattern = r'\d+:\s+(\S+):'
            iface_match = re.search(interface_pattern, output)
            if iface_match:
                IPV6_INTERFACE = iface_match.group(1)
            else:
                IPV6_INTERFACE = 'eth0'  # 默认
        
        print(f"{colors.GREEN}[IPv6]{colors.RESET} 自动检测到前缀: {IPV6_PREFIX}")
        print(f"{colors.GREEN}[IPv6]{colors.RESET} 自动检测到网卡: {IPV6_INTERFACE}")
        return True
        
    except Exception as e:
        print(f"{colors.YELLOW}[警告]{colors.RESET} 自动检测IPv6失败: {e}")
        return False

def get_next_ipv6():
    """获取下一个可用的IPv6地址（线程安全）"""
    global current_ip_index
    
    if not IPV6_PREFIX:
        return None
    
    with ipv6_lock:
        # 生成IPv6地址的后64位（接口标识）
        ip_suffix = current_ip_index
        current_ip_index += 1
        
        # 如果超过最大索引，重新从0开始（循环使用）
        if current_ip_index >= max_ip_index:
            current_ip_index = 0
            
        # 生成完整的IPv6地址
        ipv6_addr = f"{IPV6_PREFIX}::{ip_suffix:x}"
        
        return ipv6_addr

def check_ipv6_available():
    """检查IPv6是否可用"""
    if not IPV6_PREFIX:
        return False
    
    try:
        # 尝试执行IPv6 ping测试
        result = subprocess.run(
            ['ping6', '-c', '1', '2001:4860:4860::8888'],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

# 全局计数器（线程安全）
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

def check_rate_limit():
    """检测限流情况，必要时调整并发数和延迟"""
    global current_workers, current_delay, consecutive_timeouts
    
    with rate_limit_lock:
        # 如果连续超时超过阈值，触发降速
        if consecutive_timeouts >= RATE_LIMIT_THRESHOLD:
            old_workers = current_workers
            old_delay = current_delay
            
            # 降低并发数（不低于最小值）
            new_workers = max(int(current_workers * WORKER_REDUCE_FACTOR), MIN_WORKERS)
            
            # 增加延迟（不超过最大值）
            new_delay = min(current_delay * DELAY_INCREASE_FACTOR, MAX_DELAY)
            
            # 更新配置
            current_workers = new_workers
            current_delay = new_delay
            
            print(f"\n{colors.MAGENTA}{'=' * 60}{colors.RESET}")
            print(f"{colors.BOLD}{colors.YELLOW}[自适应限流]{colors.RESET} 检测到连续 {consecutive_timeouts} 次超时")
            print(f"{colors.YELLOW}调整前:{colors.RESET} 并发 {old_workers}, 延迟 {old_delay:.1f}秒")
            print(f"{colors.GREEN}调整后:{colors.RESET} 并发 {new_workers}, 延迟 {new_delay:.1f}秒")
            print(f"{colors.MAGENTA}{'=' * 60}{colors.RESET}\n")
            
            # 重置计数器
            consecutive_timeouts = 0
            
            return True
        return False

def record_timeout():
    """记录一次超时，并检查是否需要降速"""
    global consecutive_timeouts
    
    with rate_limit_lock:
        consecutive_timeouts += 1
        total_timeouts = counter.add_timeout()
    
    # 每检查一定数量域名后，检测限流情况
    checked = counter.checked
    if checked % RATE_CHECK_INTERVAL == 0:
        check_rate_limit()

def get_current_config():
    """获取当前配置（线程安全）"""
    with rate_limit_lock:
        return current_workers, current_delay

def load_dictionary(dict_file):
    """从文件加载字典前缀"""
    if not os.path.exists(dict_file):
        print(f"{colors.RED}[错误]{colors.RESET} 字典文件 '{dict_file}' 不存在")
        sys.exit(1)
    
    with open(dict_file, 'r', encoding='utf-8') as f:
        prefixes = [line.strip() for line in f 
                   if line.strip() and not line.startswith('#')]
    
    print(f"{colors.CYAN}[信息]{colors.RESET} 已加载 {colors.BOLD}{len(prefixes)}{colors.RESET} 个前缀")
    return prefixes

def load_cache():
    """加载已检查过的域名缓存"""
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
    """将已检查域名追加到缓存（线程安全）"""
    with file_lock:
        try:
            with open(CACHE_FILE, 'a', encoding='utf-8') as f:
                f.write(f"{domain}\n")
        except Exception as e:
            print(f"{colors.RED}[错误]{colors.RESET} 写入缓存失败: {e}")

def save_available(domain, output_file):
    """保存可用域名（线程安全）"""
    with file_lock:
        try:
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(f"{domain}\n")
        except Exception as e:
            print(f"{colors.RED}[错误]{colors.RESET} 写入结果失败: {e}")

def check_domain_with_ipv6(domain, source_ip):
    """
    使用指定IPv6源地址查询域名
    包含完整的防封机制和自适应限流
    """
    workers, delay = get_current_config()
    
    for attempt in range(MAX_RETRIES):
        try:
            # 随机抖动 - 避免规律性请求
            jitter = random.uniform(0.1, 0.5)
            time.sleep(jitter)
            
            # 执行WHOIS查询
            result = subprocess.run(
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=REQUEST_TIMEOUT,
                env={'LANG': 'C'}
            )
            
            output = result.stdout.lower()
            
            # === 检测限流 ===
            limit_indicators = [
                'limit', 'exceeded', 'denied', 'refused', 
                'too many', 'rate limit', 'try again later',
                'error 55000000003',  # .de 限流码
                'connection refused'
            ]
            
            for indicator in limit_indicators:
                if indicator in output:
                    if attempt < MAX_RETRIES - 1:
                        # 记录限流事件
                        record_timeout()
                        
                        # 指数退避：被限流时等待更长时间
                        wait_time = delay * (2 ** attempt)
                        wait_time = min(wait_time, MAX_DELAY)
                        
                        print(f"{colors.YELLOW}[限流]{colors.RESET} {domain} "
                              f"(IP: {source_ip}) 被限流，"
                              f"等待 {wait_time:.1f}秒后重试 ({attempt+1}/{MAX_RETRIES})")
                        time.sleep(wait_time)
                        break
                    else:
                        print(f"{colors.RED}[限流]{colors.RESET} {domain} "
                              f"重试{MAX_RETRIES}次仍失败，跳过")
                        record_timeout()  # 记录失败
                        return False
            
            # ========== 规则1: 明确的未注册关键词 ==========
            strong_available = [
                'no match',
                'no entries found',
                'not found',
                'no object found',
                'not registered',
                'no data found',
                'domain is available',
                'status: free',
                '% not registered',
                'no matching object',
                'the queried object does not exist'  # .im
            ]
            
            for indicator in strong_available:
                if indicator in output:
                    return True
            
            # ========== 规则2: 明确的已注册关键词 ==========
            strong_registered = [
                'domain name:',
                'registrar:',
                'registrant name:',
                'registrant organization:',
                'name server:',
                'domain status:',
                'creation date:',
                'expiry date:',
                'updated date:',
                'whois server:',
                'referral url:'
            ]
            
            for indicator in strong_registered:
                if indicator in output:
                    return False
            
            # ========== 规则3: TLD特殊规则 ==========
            tld = domain.split('.')[-1]
            
            if tld == 'de':
                if 'status: free' in output:
                    return True
            
            if tld == 'im':
                if 'not registered' in output:
                    return True
                if 'the queried object does not exist' in output:
                    return True
            
            if tld == 'pw':
                if 'no entries found' in output:
                    return True
            
            # ========== 规则4: 启发式判断 ==========
            # 如果输出非常短（<200字符），很可能是未注册
            if len(output) < 200:
                error_indicators = ['error', 'limit', 'denied', 'refused', 'timeout']
                if not any(e in output for e in error_indicators):
                    return True
            
            # 如果输出很长（>1000字符），几乎肯定是已注册
            if len(output) > 1000:
                return False
            
            # 默认保守判断：不可用
            return False
            
        except subprocess.TimeoutExpired:
            # 记录超时事件
            record_timeout()
            
            if attempt < MAX_RETRIES - 1:
                workers, delay = get_current_config()  # 重新获取最新配置
                wait_time = delay * (2 ** attempt)
                wait_time = min(wait_time, MAX_DELAY)
                print(f"{colors.YELLOW}[超时]{colors.RESET} {domain} (IP: {source_ip}) "
                      f"查询超时，等待 {wait_time:.1f}秒后重试 ({attempt+1}/{MAX_RETRIES})")
                time.sleep(wait_time)
            else:
                print(f"{colors.RED}[超时]{colors.RESET} {domain} "
                      f"重试{MAX_RETRIES}次仍超时，跳过")
                return False
                
        except Exception as e:
            record_timeout()
            
            if attempt < MAX_RETRIES - 1:
                workers, delay = get_current_config()
                wait_time = delay * (2 ** attempt)
                wait_time = min(wait_time, MAX_DELAY)
                print(f"{colors.YELLOW}[错误]{colors.RESET} {domain} (IP: {source_ip}) - {str(e)[:50]}，"
                      f"等待 {wait_time:.1f}秒后重试 ({attempt+1}/{MAX_RETRIES})")
                time.sleep(wait_time)
            else:
                print(f"{colors.RED}[错误]{colors.RESET} {domain} - {str(e)[:50]}，"
                      f"重试{MAX_RETRIES}次失败，跳过")
                return False
    
    return False

def worker(domain, output_file):
    """单个域名查询工作线程（使用不同IPv6源地址）"""
    # 为这个线程分配一个IPv6源地址
    source_ip = get_next_ipv6() if USE_IPV6 else "IPv6禁用"
    
    try:
        is_available = check_domain_with_ipv6(domain, source_ip)
    except Exception as e:
        print(f"{colors.RED}[严重错误]{colors.RESET} {domain}: {e}")
        is_available = False
    
    # 保存到缓存（无论是否可用）
    save_to_cache(domain)
    
    # 更新计数器
    checked = counter.add_checked()
    
    if is_available:
        save_available(domain, output_file)
        available = counter.add_available()
        status = f"{colors.GREEN}可用{colors.RESET}"
    else:
        available = counter.available
        status = f"{colors.RED}不可用{colors.RESET}"
    
    # 获取当前配置用于显示
    workers, delay = get_current_config()
    
    # 打印进度（每10个或发现可用时打印）
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
              f"{domain} {ip_info} - {status} "
              f"(可用: {colors.GREEN}{available}{colors.RESET}"
              f"{colors.CYAN}{eta_str}{colors.RESET}) "
              f"[并发:{workers} 延迟:{delay:.1f}s 超时:{timeouts}]")

def init_ipv6():
    """初始化IPv6配置"""
    global USE_IPV6, IPV6_PREFIX, IPV6_INTERFACE
    
    if not USE_IPV6:
        return False
    
    print(f"{colors.CYAN}[IPv6]{colors.RESET} 正在自动检测IPv6配置...")
    
    # 自动检测IPv6前缀和网卡
    if not detect_ipv6_prefix():
        print(f"{colors.YELLOW}[警告]{colors.RESET} 自动检测IPv6失败，将使用普通模式")
        USE_IPV6 = False
        return False
    
    # 检查IPv6网络是否可用
    if not check_ipv6_available():
        print(f"{colors.YELLOW}[警告]{colors.RESET} IPv6网络可能不可用，将尝试继续")
    
    # 检查是否已有IPv6地址
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
    global current_workers, current_delay
    
    parser = argparse.ArgumentParser(description='高性能域名批量查询工具 - IPv6多IP并发版（自适应限流）')
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
                       help=f'最大重试次数，默认: {MAX_RETRIES}')
    parser.add_argument('--max-ips', type=int, default=1000,
                       help=f'最大使用IPv6数量，默认: 1000')
    parser.add_argument('--threshold', type=int, default=RATE_LIMIT_THRESHOLD,
                       help=f'限流触发阈值（连续超时次数），默认: {RATE_LIMIT_THRESHOLD}')
    parser.add_argument('--no-ipv6', action='store_true',
                       help='禁用IPv6多IP功能')
    parser.add_argument('--no-cache', action='store_true',
                       help='不使用缓存')
    parser.add_argument('--no-color', action='store_true',
                       help='强制不使用颜色')
    args = parser.parse_args()
    
    # 根据字典名和TLD生成输出文件名
    dict_name = os.path.splitext(os.path.basename(args.dictionary))[0]
    tlds = args.tld
    tld_str = "-".join(tlds)
    OUTPUT_FILE = f"{dict_name}-{tld_str}可注册.txt"
    
    # 更新配置
    global MIN_WORKERS, RATE_LIMIT_THRESHOLD
    MIN_WORKERS = args.min_workers
    RATE_LIMIT_THRESHOLD = args.threshold
    max_ip_index = args.max_ips
    BASE_DELAY = args.delay
    MAX_DELAY = args.max_delay
    REQUEST_TIMEOUT = args.timeout
    MAX_RETRIES = args.retries
    current_workers = args.workers
    current_delay = BASE_DELAY
    
    if args.no_ipv6:
        USE_IPV6 = False
    
    if args.no_color:
        colors.supported = False
        colors.__init__()
    
    max_workers = current_workers  # 初始并发数
    use_cache = not args.no_cache
    
    # 打印配置
    separator = f"{colors.BLUE}{'=' * 80}{colors.RESET}"
    print(separator)
    print(f"{colors.BOLD}{colors.CYAN}高性能域名批量查询工具 - IPv6多IP并发版（自适应限流）{colors.RESET}")
    print(f"{colors.YELLOW}字典文件:{colors.RESET} {args.dictionary}")
    print(f"{colors.YELLOW}输出文件:{colors.RESET} {OUTPUT_FILE}")
    print(f"{colors.YELLOW}查询TLD:{colors.RESET} {tlds}")
    print(f"{colors.YELLOW}初始并发:{colors.RESET} {max_workers}")
    print(f"{colors.YELLOW}最小并发:{colors.RESET} {MIN_WORKERS}")
    print(f"{colors.YELLOW}限流阈值:{colors.RESET} {RATE_LIMIT_THRESHOLD}次超时")
    print(f"{colors.YELLOW}最大IPv6数:{colors.RESET} {max_ip_index}")
    print(f"{colors.YELLOW}基础延迟:{colors.RESET} {BASE_DELAY}秒")
    print(f"{colors.YELLOW}最大延迟:{colors.RESET} {MAX_DELAY}秒")
    print(f"{colors.YELLOW}查询超时:{colors.RESET} {REQUEST_TIMEOUT}秒")
    print(f"{colors.YELLOW}最大重试:{colors.RESET} {MAX_RETRIES}次")
    print(f"{colors.YELLOW}使用缓存:{colors.RESET} {use_cache}")
    print(separator)
    
    # 初始化IPv6
    if USE_IPV6:
        USE_IPV6 = init_ipv6()
    
    # 加载数据
    prefixes = load_dictionary(args.dictionary)
    cached = load_cache() if use_cache else set()
    
    # 生成查询列表
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
    
    # 开始多线程查询
    print(f"{colors.CYAN}启动 {max_workers} 个线程并发查询...{colors.RESET}\n")
    start_time = time.time()
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务，传入输出文件名
            futures = [executor.submit(worker, domain, OUTPUT_FILE) for domain in all_domains]
            
            # 等待所有完成
            for future in as_completed(futures):
                future.result()  # 如果有异常会在这里抛出
    
    except KeyboardInterrupt:
        print(f"\n\n{colors.RED}[警告]{colors.RESET} 用户中断，正在等待当前任务完成...")
        # ThreadPoolExecutor 会在上下文退出时自动等待
    
    finally:
        total_time = time.time() - start_time
        checked, available, timeouts = counter.get()
        speed = checked / total_time if total_time > 0 else 0
        
        print("\n" + separator)
        print(f"{colors.BOLD}{colors.GREEN}查询完成{colors.RESET}")
        print(f"{colors.CYAN}总共检查:{colors.RESET} {colors.BOLD}{checked}{colors.RESET} 个域名")
        print(f"{colors.CYAN}发现可用:{colors.RESET} {colors.BOLD}{colors.GREEN}{available}{colors.RESET} 个域名")
        print(f"{colors.CYAN}超时/限流:{colors.RESET} {colors.BOLD}{timeouts}{colors.RESET} 次")
        print(f"{colors.CYAN}最终并发:{colors.RESET} {colors.BOLD}{current_workers}{colors.RESET}")
        print(f"{colors.CYAN}最终延迟:{colors.RESET} {colors.BOLD}{current_delay:.1f}{colors.RESET}秒")
        print(f"{colors.CYAN}总耗时:{colors.RESET} {colors.BOLD}{total_time/60:.1f}{colors.RESET} 分钟")
        print(f"{colors.CYAN}平均速度:{colors.RESET} {colors.BOLD}{speed:.2f}{colors.RESET} 个/秒")
        print(f"{colors.CYAN}可用域名已保存到:{colors.RESET} {OUTPUT_FILE}")
        print(f"{colors.CYAN}缓存文件:{colors.RESET} {CACHE_FILE}")
        print(separator)

if __name__ == "__main__":
    main()
