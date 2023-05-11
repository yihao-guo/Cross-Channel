#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#相应的所需要提供的信息，例如server的账户密码以及ip等
import threading

USERNAME = ''  # username of servers
PASSWD = ''  # password of servers  
MAXPAYLOAD =  # maximum number of containers running on one server 单个ip最大的容器数
NODE_COUNT =  # 主机个数 * MAXPAYLOAD   #所有节点数:最大为主机数×MAXPAYLOAD  
IP_CONFIG = 'ip.txt'  # server IPs
SECONDS_IN_A_DAY = 60 * 60 * 24
SEMAPHORE = threading.BoundedSemaphore(15)
ABI = ''
BIN = ''
