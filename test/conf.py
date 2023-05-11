#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 16 11:04:55 2019

@author: rkd

genesis文件初始化
"""

import json
import time


def generate_genesis_poa(chain_id, accounts, config_file):
    """Generate a genesis file."""
    with open('dockertest/poa.json', 'rb') as f:
        genesis = json.load(f)
    genesis['config']['chainId'] = chain_id
    # min_nums = 4
    min_accounts = []
    # for i in range(min_nums):5
    # min_accounts.append(accounts[i])
    genesis['extraData'] = '0x' + '0'*64 + ''.join(accounts[0]) + '0' * 130

    # pub_nums = NODE_COUNT
    pub_accounts = []
    # for i in range(1, pub_nums):
    pub_accounts.append(accounts[1])
    pub_accounts.append(accounts[2])
    for acc in pub_accounts:
        genesis['alloc'][acc] = {
            'balance': "0x2000000000"}
    new_genesis = json.dumps(genesis, indent=2)
    with open(config_file, 'w') as f:
        print(new_genesis, file=f)
    time.sleep(0.05)


def generate_genesis_pow(chain_id, accounts, config_file):
    """Generate a genesis file."""
    with open('dockertest/pow.json', 'rb') as f:  # 先打开本地json，在上面进行修改
        genesis = json.load(f)
    genesis['config']['chainId'] = chain_id
    for acc in accounts:
        genesis['alloc'][acc] = {
            'balance': "0x400000000000000000000000"}  # 添加账户和余额

    new_genesis = json.dumps(genesis, indent=2)  # ident 缩进相关
    with open('%s' % config_file, 'w') as f:
        print(new_genesis, file=f)
    time.sleep(0.05)
