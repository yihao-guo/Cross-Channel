#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#from solc import compile_files

from const import USERNAME, PASSWD, NODE_COUNT, IP_CONFIG, ABI, BIN
from gethnode import GethNode
from iplist import IPList
from conf import generate_genesis_pow
from functools import wraps
import time
import subprocess
import threading
from resultthread import MyThread
from web3 import Web3
import numpy as np
from solc import compile_files


class SingleChain():
    """
    Data structure for a set of Geth-pbft clients for a single blockchain.
    """
    def __init__(self, name, node_count, blockchain_id, ip_list, username=USERNAME, password=PASSWD):

        # Check if the input params are legal.
        if node_count > ip_list.get_full_count():
            raise ValueError("not enough IPs")

        self.username = username
        self.password = password
        self.chain_id = name    # chain id
        self.node_count = node_count
        self.blockchain_id = blockchain_id
        self.ip_list = ip_list
        self.nodes = []
        self.ips = set()
        self.if_set_number = False
        self.if_set_id = False
        self.is_terminal = False
        self.config_file = None
        self.accounts = []

    def singlechain_start(self):
        """Start all containers for a single chain."""
        threads = []
        for index in range(self.node_count):
            node_index = index + 1
            tmp = GethNode(self.ip_list, node_index, self.blockchain_id, self.username, self.password)
            self.ips.add(tmp.ip)
            self.nodes.append(tmp)
            # xq start a thread， target stand for a function that you want to run ,args stand for the parameters
            t = threading.Thread(target=tmp.start)
            t.start()
            threads.append(t)
            time.sleep(0.3)

        for t in threads:
            # xq threads must run the join function, because the resources of main thread is needed
            t.join()

        for index in range(self.node_count):
            print(index, self.nodes[index].accounts[0])
            self.accounts.append(self.nodes[index].accounts[0])
        print('The corresponding accounts are as follows:')
        print(self.accounts)

    def set_genesis(config):
        """Decorator for setting genesis.json file for a chain."""

        @wraps(config)
        def func(self, *args):
            config(self, *args)
            for server_ip in self.ips:
                #  将config_file远程发送到主机里
                subprocess.run(['sshpass -p %s scp %s %s@%s:%s' % (self.password, self.config_file,
                               self.username, server_ip.address, self.config_file)], stdout=subprocess.PIPE, shell=True)
                time.sleep(0.2)
                threads = []
                for node in self.nodes:
                    if node.ip == server_ip:
                        #  对于每个容器  将config_file 从主机copy到容器/root/目录下
                        command = 'docker cp %s %s:/root/%s' % (self.config_file, node.name, self.config_file)
                        t = threading.Thread(target=server_ip.exec_command, args=(command,))
                        t.start()
                        threads.append(t)
                        print('copying genesis file')
                        #  node._ifSetGenesis = True
                        time.sleep(0.1)
                for t in threads:
                    t.join()
            time.sleep(0.5)
        return func

    @set_genesis
    def config_consensus_chain(self):
        """Set genesis.json for a blockchain & init with genesis.json."""
        if self.chain_id is "":
            self.config_file = '0.json'
        else:
            self.config_file = '%s.json' % self.chain_id
        generate_genesis_pow(self.blockchain_id, self.accounts, self.config_file)
        time.sleep(0.02)

    def get_logs(self):
        for server_ip in self.ips:
            #  将log日志从容器复制到服务器主机里
            threads = []
            for node in self.nodes:
                if node.ip == server_ip:
                    #  对于每个容器  将log文件从到容器/root/目录下copy到主机
                    command = 'docker cp %s:path' % (node.name)
                    t = threading.Thread(target=server_ip.exec_command, args=(command,))
                    t.start()
                    threads.append(t)
                    print('copying log file')
                    time.sleep(0.1)
            for t in threads:
                t.join()
            time.sleep(0.2)
            subprocess.run(['sshpass -p %s scp %s@%s:%s %s' % (self.password, self.username, server_ip.address,
                                                               'evs-test85*', 'path')],
                           stdout=subprocess.PIPE, shell=True)

        time.sleep(0.5)

    @set_genesis
    def config_terminal(self):
        """Set genesis.json for terminal equipments."""
        if len(self.chain_id) == 4:
            self.config_file = '0.json'
        else:
            self.config_file = '%s.json' % self.chain_id[:-4]

    def get_chain_id(self):
        """return chain id of the chain."""
        return self.chain_id

    def get_primer_node(self):
        """Return the primer node of the set of Geth-pbft clients."""
        return self.nodes[0]

    def get_node_by_index(self, node_index):
        """Return the node of a given index."""
        if node_index <= 0 or node_index > len(self.nodes):
            raise ValueError("node index out of range")
        return self.nodes[node_index-1]

    def run_nodes(self):
        """Run nodes on a chain."""
        self.init_geth()
        self.run_geth_nodes()
        self.construct_chain()

    def init_geth(self):
        """
        run geth init command for nodes in a chain
        """
        print("self.config_file =", self.config_file)
        if self.config_file is None:
            raise ValueError("initID is not set")
        threads = []
        for server_ip in self.ips:
            for node in self.nodes:
                if node.ip == server_ip:
                    init_geth_command = 'docker exec -t %s geth --datadir abc init %s' % (node.name, self.config_file)
                    t = threading.Thread(target=server_ip.exec_command, args=(init_geth_command,))
                    t.start()
                    threads.append(t)
                    time.sleep(0.1)
        for t in threads:
            t.join()

    def run_geth_nodes(self):
        threads = []
        for node in self.nodes:
            start_geth_command = (
                                     'geth --experiment.output=path  --datadir abc --networkid 55661 --port 30303 --http --http.addr 0.0.0.0 --http.port 8545 --http.api '
                                     'admin,eth,miner,web3,net,personal,txpool  --http.corsdomain \\"*\\" '
                                     '--unlock %s --password passfile -allow-insecure-unlock 2>>%s.log') % (
                                 node.accounts[0], node.name)

            #--rpc --rpcport 8485 --rpcapi eth,web3,net,personal --allow-insecure-unlock --port 30301 --networkid  29381

            print(node.name)
            print("start_geth_command------------", start_geth_command)
            command = 'docker exec -d %s bash -c \"%s\" ' % (node.name, start_geth_command)  # 主机内执行的完整命令
            print("docker_command------------", command)
            t = threading.Thread(target=node.ip.exec_command, args=(command,))  # 通过ip执行
            t.start()
            threads.append(t)
            time.sleep(0.5)
        for t in threads:
            t.join()
        print('node starting......')
        time.sleep(1)
        # must wait here
        for _ in range(3):
            print('.', end='')
            time.sleep(1)

        threads = []
        for node in self.nodes:
            t = threading.Thread(target=node.set_enode)  # 设置client的enode信息
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        print("---------------------set node---------------------")
        for node in self.nodes:
            node.set_enode()
        time.sleep(0.1)

    def construct_chain(self):
        """Construct a single chain.节点互联"""
        if not self.is_terminal:
            print("constructing single chain......")
            start_time = time.time()
            threads = []
            node_count = len(self.nodes)

            # connect nodes in a single chain with each other
            for i in range(node_count):  # (node_count)
                for j in range(i+1, node_count):  # (i+1,node_count)
                    print("---------------------add peer---------------------")
                    t1 = threading.Thread(target=self.nodes[i].add_peer, args=(self.nodes[j].enode,))
                    t1.start()
                    time.sleep(0.1)  # if fail. add this line.
                    threads.append(t1)
                # break
            for t in threads:
                t.join()
            print("-------------------------")
            print('active threads:', threading.active_count())
            end_time = time.time()
            print('active time:%.3fs' % (end_time - start_time))
            print("-------------------------")
            time.sleep(len(self.nodes) // 10)

    def destruct_chain(self):
        """Stop containers to destruct the chain."""
        threads = []
        for node in self.nodes:
            t = threading.Thread(target=node.stop)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def get_node_count(self):
        """Return the number of nodes of the blockchain."""
        return len(self.nodes)

    def start_miner(self):
        """Start miners of all nodes on the chain."""
        if not self.is_terminal:
            threads = []
            for node in self.nodes:
                t = threading.Thread(target=node.start_miner)
                t.start()
                threads.append(t)
                time.sleep(0.02)
            for t in threads:
                t.join()

# --------------------------------test-mul--------------------------------
# 发送批量交易函数


def test_send_mul_converts(convert_num, nodes, accounts):
    threads = []
    for i in range(convert_num):
        t = MyThread(nodes[i].send_mulconvert_transaction, args=(accounts[i],))
        threads.append(t)
        time.sleep(1)
    for t in threads:
        t.start()
        time.sleep(1)
    for t in threads:
        t.join()

    convert_end_time = []
    for t in threads:
        try:
            t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            t2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        print("get t2 ==", t2)

        convert_end_time = convert_end_time + t2
        convert_end_time = sorted(convert_end_time, reverse=False)
    return convert_end_time


def test_send_mul_commits(convert_num, nodes, accounts, arr):
    threads = []
    for i in range(convert_num):
        t = MyThread(nodes[i].send_mulcommit_transaction, args=(accounts[i], arr))
        threads.append(t)
        time.sleep(1)
    for t in threads:
        t.start()
        time.sleep(1)
    for t in threads:
        t.join()

    convert_end_time = []
    for t in threads:
        try:
            t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            t2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        print("get t2 ==", t2)

        convert_end_time = convert_end_time + t2
        convert_end_time = sorted(convert_end_time, reverse=False)
    return convert_end_time


def test_send_mul_claims(convert_num, nodes, accounts, arr):
    threads = []
    for i in range(convert_num):
        t = MyThread(nodes[i].send_mulclaim_transaction, args=(accounts[i], arr))
        threads.append(t)
        time.sleep(1)
    for t in threads:
        t.start()
        time.sleep(1)
    for t in threads:
        t.join()

    convert_end_time = []
    for t in threads:
        try:
            t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            t2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        print("get t2 ==", t2)

        convert_end_time = convert_end_time + t2
        convert_end_time = sorted(convert_end_time, reverse=False)
    return convert_end_time

def test_send_mul_refunds(convert_num, nodes, accounts, arr):
    threads = []
    for i in range(convert_num):
        t = MyThread(nodes[i].send_mulrefund_transaction, args=(accounts[i], arr))
        threads.append(t)
        time.sleep(1)
    for t in threads:
        t.start()
        time.sleep(1)
    for t in threads:
        t.join()

    convert_end_time = []
    for t in threads:
        try:
            t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            t2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        print("get t2 ==", t2)

        convert_end_time = convert_end_time + t2
        convert_end_time = sorted(convert_end_time, reverse=False)
    return convert_end_time


def test_send_mul_deposits(convert_num, nodes, accounts):
    threads = []
    for i in range(convert_num):
        t = MyThread(nodes[i].send_muldeposit_transaction, args=(accounts[i],))
        threads.append(t)
        time.sleep(1)
    for t in threads:
        t.start()
        time.sleep(1)
    for t in threads:
        t.join()

    convert_end_time = []
    for t in threads:
        try:
            t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            t2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        print("get t2 ==", t2)

        convert_end_time = convert_end_time + t2
        convert_end_time = sorted(convert_end_time, reverse=False)
    return convert_end_time


####################################################################################################################
# test_get_mul_contractaddr 批量产生智能合约地址


def test_get_mul_contractaddr(contract_num, nodes):
    threads = []
    t1 = time.time()
    for i in range(contract_num):
        t = MyThread(nodes[i].get_contractaddr)
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    t2 = time.time()
    test_get_mul_contractaddr_time = t2 - t1
    print("test_get_mul_contractaddr_time =", test_get_mul_contractaddr_time)
    contractaddr_list = []
    for t in threads:
        try:
            contractaddr = t.get_result()  # contractaddr为部署合约的地址
        except:
            contractaddr = "0x1"
        contractaddr_list.append(contractaddr)
    return contractaddr_list

# 单笔交易发送函数
# test_send_mul_mint


def test_send_mul_mint(mint_num, nodes, accounts, test_nodes):
    threads = []
    for i in range(mint_num):
        t = MyThread(nodes[i].send_mint_transaction, args=(accounts[i], "0x7d0", test_nodes[i]))
        threads.append(t)
        time.sleep(2)
    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()
    mint_exec_time = []
    mint_consensus_time = []
    mint_hash_list = []
    for t in threads:
        try:
            mint_hash, consensus_time, exec_time = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            mint_hash = "0x1"
            consensus_time = 0
        mint_hash_list.append(mint_hash)
        mint_consensus_time.append(consensus_time)
        mint_exec_time.append(exec_time)
    mint_consensus_totaltime = 0
    for i in range(mint_num):
        mint_consensus_totaltime += mint_consensus_time[i]
    mint_consensus_avetime = mint_consensus_totaltime/mint_num
    mint_exec_totaltime = 0
    for i in range(mint_num):
        mint_exec_totaltime += mint_exec_time[i]
    mint_exec_avetime = mint_exec_totaltime / mint_num
    return mint_hash_list, mint_consensus_avetime, mint_exec_avetime


# test_send_mul_convert
def test_send_mul_convert(convert_num, nodes, accounts, test_nodes):
    threads = []
    for i in range(convert_num):
        t = MyThread(nodes[i].send_convert_transaction, args=(accounts[i], test_nodes[i]))

        threads.append(t)
        time.sleep(2)
    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()
    convert_hash_list = []
    convert_start_time = []
    convert_end_time = []
    for t in threads:
        try:
            convert_hash, t1, t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            convert_hash = "0x1"
            # t1 = 0
            # t2 = 0
        convert_hash_list.append(convert_hash)
        convert_start_time.append(t1)
        convert_end_time.append(t2)
        convert_start_time = sorted(convert_start_time, reverse=False)
        convert_end_time = sorted(convert_end_time, reverse=False)
    return convert_hash_list, convert_start_time, convert_end_time


# test_send_mul_commit
def test_send_mul_commit(commit_num, nodes, accounts, contractaddr, test_nodes):
    threads = []
    for i in range(commit_num):
        t = MyThread(nodes[i].send_commit_transaction, args=(accounts[i], contractaddr, test_nodes[i]))
        threads.append(t)
        time.sleep(2)
    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()
    commit_hash_list = []
    commit_start_time = []
    commit_end_time = []
    for t in threads:
        try:
            commit_hash, t1, t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            commit_hash = "0x1"
            consensus_time = 0
            exec_time = 0
        commit_hash_list.append(commit_hash)
        commit_start_time.append(t1)
        commit_end_time.append(t2)
        commit_start_time = sorted(commit_start_time, reverse=False)
        commit_end_time = sorted(commit_end_time, reverse=False)
    return commit_hash_list, commit_start_time, commit_end_time


# test_send_mul_claim
def test_send_mul_claim(claim_num, nodes, accounts, contractaddr, addrA, test_nodes):
    threads = []
    for i in range(claim_num):
        t = MyThread(nodes[i].send_claim_transaction, args=(accounts[i], contractaddr, addrA[i], test_nodes[i]))
        threads.append(t)
        time.sleep(2)
    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()
    claim_hash_list = []
    claim_start_time = []
    claim_end_time = []
    for t in threads:
        try:
            claim_hash, t1, t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            claim_hash = "0x1"
            # consensus_time = 0
            # exec_time = 0
        claim_hash_list.append(claim_hash)
        claim_start_time.append(t1)
        claim_end_time.append(t2)
        claim_start_time = sorted(claim_start_time, reverse=False)
        claim_end_time = sorted(claim_end_time, reverse=False)
    # claim_consensus_totaltime = 0
    # for i in range(claim_num):
    #     claim_consensus_totaltime += claim_consensus_time[i]
    # claim_consensus_avetime = claim_consensus_totaltime/claim_num
    # claim_exec_totaltime = 0
    # for i in range(claim_num):
    #     claim_exec_totaltime += claim_exec_time[i]
    # claim_exec_avetime = claim_exec_totaltime / claim_num
    return claim_hash_list, claim_start_time, claim_end_time


# test_send_mul_rerfund
def test_send_mul_refund(refund_num, nodes, accounts, contractaddr, test_nodes):
    threads = []
    for i in range(refund_num):
        t = MyThread(nodes[i].send_refund_transaction, args=(accounts[i], contractaddr, test_nodes[i]))
        threads.append(t)
        time.sleep(2)
    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()
    refund_hash_list = []
    refund_start_time = []
    refund_end_time = []
    for t in threads:
        try:
            refund_hash, t1, t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            refund_hash = "0x1"
            # consensus_time = 0
            # exec_time = 0
        refund_hash_list.append(refund_hash)
        refund_start_time.append(t1)
        refund_end_time.append(t2)
        refund_start_time = sorted(refund_start_time, reverse=False)
        refund_end_time = sorted(refund_end_time, reverse=False)
    # refund_consensus_totaltime = 0
    # for i in range(refund_num):
    #     refund_consensus_totaltime += refund_consensus_time[i]
    # refund_consensus_avetime = refund_consensus_totaltime/refund_num
    # refund_exec_totaltime = 0
    # for i in range(refund_num):
    #     refund_exec_totaltime += refund_exec_time[i]
    # refund_exec_avetime = refund_exec_totaltime / refund_num
    return refund_hash_list, refund_start_time, refund_end_time


"""test_send_mul_deposit"""


def test_send_mul_deposit(deposit_num, nodes, accounts, N, test_nodes):
    threads = []
    for i in range(deposit_num):
        t = MyThread(nodes[i].send_depositsg_transaction, args=(accounts[i], N, test_nodes[i]))
        threads.append(t)
        time.sleep(2)
    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()
        time.sleep(1)
    deposit_hash_list = []
    deposit_start_time = []
    deposit_end_time = []
    for t in threads:
        try:
            deposit_hash, t1, t2 = t.get_result()  # consensus_time是从产生hash到打包到区块的时间
        except:
            deposit_hash = "0x1"
            consensus_time = 0
            exec_time = 0
        deposit_hash_list.append(deposit_hash)
        deposit_start_time.append(t1)
        deposit_end_time.append(t2)
        deposit_start_time = sorted(deposit_start_time, reverse=False)
        deposit_end_time = sorted(deposit_end_time, reverse=False)
    # deposit_consensus_totaltime = 0
    # for i in range(deposit_num):
    #     deposit_consensus_totaltime += deposit_consensus_time[i]
    # deposit_consensus_avetime = deposit_consensus_totaltime/deposit_num
    # deposit_exec_totaltime = 0
    # for i in range(deposit_num):
    #     deposit_exec_totaltime += deposit_exec_time[i]
    # deposit_exec_avetime = deposit_exec_totaltime / deposit_num
    return deposit_hash_list, deposit_start_time, deposit_end_time


def test_node(nodesa , accountsa):
    """可用于测试节点是否工作 ， 除去不工作的节点"""
    threads = []
    node_count = len(nodesa)
    for i in range(node_count):
        t = MyThread(nodesa[i].get_peer_count)
        threads.append(t)
        time.sleep(2)
    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()
    tmp = 0
    for i, t in enumerate(threads):
        if(t.get_result() == None):
            nodesa[i] = 0
            accountsa[i] = 0
            # hash_list[i] = 0
            tmp += 1
            node_count -= 1

    for i in range(tmp):
        nodesa.remove(0)
        accountsa.remove(0)
        # hash_list.remove(0)

    print("----------------------alive_Node-------------------")
    print("nodesa = ", nodesa)
    print("accountsa = ", accountsa)
    # print("hash_list = ", hash_list)
    return node_count


# --------------------------------------------------------------------------------------------------------------------

def send_mul_redeem(redeem_num, nodes, accos, test_node):
    redeem_tran_time = []
    threads = []
    t1 = time.time()
    for i in range(redeem_num):
        t = MyThread(nodes[i].send_redeem_transaction, args=(accos[i], "0x10", test_node[i]))
        threads.append(t)
        time.sleep(2)
    for t in threads:
        t.start()
        time.sleep(2)
    for t in threads:
        t.join()
    t2 = time.time()
    print("redeem_time", t2 - t1)  # 30s
    redeem_hash_list = []
    for t in threads:
        try:
            redeem_hash, t_consen = t.get_result()
        except:
            redeem_hash = "0x1"
            t_consen = 0
        redeem_hash_list.append(redeem_hash)
        redeem_tran_time.append(t_consen)
    print(redeem_hash_list)
    print(redeem_tran_time)
    return redeem_hash_list, redeem_tran_time

# 批量挖矿
def mul_miner_start(nodes):
    threads = []
    for i in range(len(nodes)):
        t = threading.Thread(nodes[i].start_miner())
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    ip_list = IPList(IP_CONFIG)
    ip_list.stop_all_containers()
    time.sleep(0.2)
    ip_list.remove_all_containers()

    c = SingleChain('evs-test', NODE_COUNT, 121, ip_list)
    c.singlechain_start() # 启动单个私有链的所有容器并生成账户
    c.config_consensus_chain() # 初始化json文件

    c.run_nodes() # 在链上运行节点

    #  开启挖矿，全部节点用于挖矿
    for i in range(1, NODE_COUNT+1):
        c.get_node_by_index(i).start_miner()
    time.sleep(5)

    # 
    # print("------------------账户列表------------------")
    accounts_A = []

    for i in range(1, NODE_COUNT+1, 1):
        accounts_A.append(c.get_node_by_index(i).get_accounts()[0])
    print("A类账户：", accounts_A)
    # print("B类账户：", accounts_B)

    # # 划分A类B类nodes
    # print("------------------nodes列表------------------")
    nodes_A = []
    # nodes_B = []
    for i in range(1, NODE_COUNT+1):
        nodes_A.append(c.get_node_by_index(i))
    print("A类nodes：", nodes_A)
    print("-----------Wait for Generate DAG------------")
    print("Please wait for some minutes......")
    time.sleep(100)
    #gyh
    print('------------------Get-Contract-Address------------------')
    #  部署合约
    print("\n")
    w3 = Web3(Web3.HTTPProvider("http://%s:%d" % (nodes_A[0].ip.address, nodes_A[0].rpc_port)))
    user = w3.eth.accounts[0]
    balance=w3.eth.getBalance(user)
    print(balance)
    w3.geth.personal.unlockAccount(user, 'root')
    #start = time.time()
    print("开始了")
    compile_sol = compile_files(['path'])
    contractid, contract_interface = compile_sol.popitem()

    tx_hash = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin']).constructor(w3.eth.accounts[0]).transact({'from': user, 'value': 32, 'gas': 4000000})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, timeout=360)
    contract_address = tx_receipt['contractAddress']
    contract_instance = w3.eth.contract(address=contract_address, abi=contract_interface['abi'])
    start = time.time()

    #send Tx
