#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from pymongo import MongoClient
import pymongo
import pyrx
import binascii
import secrets
import struct
from Cryptodome.Util.number import long_to_bytes
import time
from web3 import Web3
import json
import datetime
import hashlib
from eth_account import Account, messages
from Crypto.Hash import keccak
import math
import traceback
from bson import json_util
import random

import rlp
from eth_typing import HexStr
from eth_utils import to_bytes, is_hex
from ethereum.transactions import Transaction

import threading
import requests
import socket


from decimal import Decimal
import math

w3 = Web3()
sender_private_key = ''
sender_address = ''
base_diff = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
assert pyrx.__version__ >= '0.0.3'
dbmongo = 'mongodb://127.0.0.1:27017'
client = MongoClient(dbmongo);
bcdb = client["eleneum"]
peers = bcdb["peers"]
blocks = bcdb["blocks"]
txs = bcdb["transactions"]
mempool = bcdb["mempool"]
balances = bcdb["balances"]
backup = bcdb["backup"]
logs = bcdb["logs"]
evm_contracts = bcdb['evm_contracts']
evm_memory = bcdb['evm_memory']
evm_internal = bcdb['evm_internal']
evm_logs = bcdb['evm_logs']
evm_transactions = bcdb['evm_transactions']
actualblock = 0
open_sockets = {}
peer_threads = {}
# Define the indexes you want to create
indices_blocks = [
    [("height", pymongo.ASCENDING)],
    [("hash", pymongo.ASCENDING)],
    [("timestamp", pymongo.ASCENDING)],
    [("prev_hash", pymongo.ASCENDING)],
]

indices_transactions = [
    [("_id", pymongo.ASCENDING)],
    [("block", pymongo.ASCENDING)],
    [("timestamp", pymongo.ASCENDING)],
    [("txinfo.hash", pymongo.ASCENDING)],
    [("txinfo.sender", pymongo.ASCENDING)],
    [("txinfo.to", pymongo.ASCENDING)],
    [("rawtx", pymongo.ASCENDING)],
    [("type", pymongo.ASCENDING)],
    [("txinfo.value", pymongo.ASCENDING)],
]

def load_config(filename):
    global sender_private_key
    global sender_address
    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        print("Error: File " + str(filename) + " not exists")
        exit(1)
    except json.JSONDecodeError as e:
        print("Error: File " + str(filename) + " is not valid")
        exit(1)

    if 'private_key' not in data:
        print("Error: File " + str(filename) + " does not contains any private key")
        exit(1)

    try:
        sender_private_key = data['private_key']
        sender_account = Account.from_key(sender_private_key)
        sender_address = sender_account.address
    except Exception as e:
        print("Error: File " + str(filename) + " contains an invalid private key")
        exit(1)
    
    print("Eleneum server started with address: " + sender_address)

def create_indexes(collection, indexes):
    for index in indexes:
        try:
            collection.create_index(index, unique=False)
            print(f"Index {index} created successfully.")
        except pymongo.errors.OperationFailure:
            print(f"Index {index} already exists, not created.")

def peer_monitor():
    while True:
        new_peers = []
        for peer in peers.find():
            server = peer['ip']
            if server not in peer_threads:
                new_thread = threading.Thread(target=launch_socket_client, args=(server,))
                peer_threads[server] = new_thread
                new_thread.start()
                new_peers.append(server)
        if new_peers:
            print(f"New peers registered: {', '.join(new_peers)}")
        time.sleep(10)

def check_elena_balance(sender, value):
    balance = balances.find_one({"account": sender})
    if balance is None:
        new_balance = {"account": sender, "value": "0"}
        balances.insert_one(new_balance)
        return False
    else:
        sender_balance = Decimal(balance["value"])
        if sender_balance >= Decimal(value):
            return True
        else:
            return False

def add_or_update_elena_balance(account, value):
    account = account.lower()
    balance = balances.find_one({"account": account})
    if balance is None:
        new_balance = {"account": account, "value": str(value)}
        balances.insert_one(new_balance)
    else:
        new_value = Decimal(balance["value"]) + Decimal(value)
        balances.update_one({"account": account}, {"$set": {"value": str(new_value)}})

    return True

def add_or_update_stake(contract, address, value, block):
    address = address.lower()
    balance = evm_memory.find_one({"contract": contract, "address": address})
    if balance is None:
        new_balance = {"contract": contract, "address": address, "value": str(value), 'block': int(block), 'reward' : "0"}
        evm_memory.insert_one(new_balance)
    else:
        new_value = Decimal(balance["value"]) + Decimal(value)
        if new_value > 0:
            evm_memory.update_one({"contract": contract, "address": address}, {"$set": {"value": str(new_value)}})
        else:
            evm_memory.delete_one({"contract": contract, "address": address})

    return True

def c_add_or_update_reward(contract, address, reward):
    address = address.lower()
    balance = evm_memory.find_one({"contract": contract, "address": address})
    if balance is None:
        return False
    else:
        if 'reward' not in balance:
            balance['reward'] = 0
        new_value = Decimal(balance["reward"]) + Decimal(reward)
        evm_memory.update_one({"contract": contract, "address": address}, {"$set": {"reward": str(new_value)}})

    return True

def c_add_or_update_balance(contract, address, value):
    address = address.lower()
    balance = evm_memory.find_one({"contract": contract, "address": address})
    if balance is None:
        new_balance = {"contract": contract, "address": address, "value": str(value)}
        evm_memory.insert_one(new_balance)
    else:
        new_value = Decimal(balance["value"]) + Decimal(value)
        evm_memory.update_one({"contract": contract, "address": address}, {"$set": {"value": str(new_value)}})

    return True

def c_get_stake(contract, sender):
    sender = sender.lower()
    balance = evm_memory.find_one({"contract": contract, "address": sender})
    if balance is None:
        return 0
    else:
        return balance["value"]
        
def get_reward(contract, sender):
    sender = sender.lower()
    balance = evm_memory.find_one({"contract": contract, "address": sender})
    if balance is None:
        return 0
    else:
        return balance["reward"]

def c_check_balance(contract, sender, value):
    sender = sender.lower()
    balance = evm_memory.find_one({"contract": contract, "address": sender})
    if balance is None:
        return False
    else:
        sender_balance = Decimal(balance["value"])
        if sender_balance >= Decimal(value):
            return True
        else:
            return False

def evm(pblock):

    # Comprobar y crear la colección evm_contracts si no existe
    if 'evm_contracts' not in bcdb.list_collection_names():
        
        evm_contracts.insert_one({
            'address': '0x0000000000000000000000000000000000000041',
            'type': 'erc20',
            'symbol': 'AL',
            'name': 'AgoraLink',
            'decimals': 18,
            'supply': '100000000000000000000000'
        })
        
        evm_contracts.insert_one({
            'address': '0x4100000000000000000000000000000000000313',
            'type': 'simplestaking',
            'staked': '',
            'reward': '0x0000000000000000000000000000000000000041',
            'blockreward': '100000000000000000000',
            'startingblock': 61500,
            'currentblock': 61500
        })

    # Comprobar y crear la colección evm_memory si no existe
    if 'evm_memory' not in bcdb.list_collection_names():
        
        evm_memory.insert_one({
            'contract': '0x0000000000000000000000000000000000000041',
            'address': '0xFda4aDBe1c4e4143B92b3947DE38427BDC1B1Fd3'.lower(),
            'value': '100000000000000000000000'
        })

    # Comprobar y crear la colección evm_internal si no existe
    if 'evm_internal' not in bcdb.list_collection_names():
        
        evm_internal.insert_one({
            'info': 'lastscannedblock',
            'value': 0
        })

    print(str(time.time()) + "EVM processing block: " + str(pblock))

    processtx = txs.find({
      'block': int(pblock),
      'txinfo.to': { '$in': ['0x0000000000000000000000000000000000000041', '0x4100000000000000000000000000000000000313'] }
    });
    
    txpc = 0

    for tx in processtx:
        txpc += 1
        if tx['txinfo']['to'] == "0x0000000000000000000000000000000000000041":
            if tx['txinfo']['data'][0:10] == '0xa9059cbb':
                sender = tx['txinfo']['sender']
                to = '0x' + tx['txinfo']['data'][34:74]
                value = int(tx['txinfo']['data'][-64:], 16)
                r = c_check_balance(tx['txinfo']['to'], sender, value)
                if r:
                    evm_logs.insert_one({"contract" : tx['txinfo']['to'], "tx" : tx["txinfo"]["hash"], "block" : tx['block'], "status" : "ok", "action" : "transfer", "from" : sender, "to": to, "value" : str(value)})
                    c_add_or_update_balance(tx['txinfo']['to'], sender, Decimal(value)*-1)
                    c_add_or_update_balance(tx['txinfo']['to'], to, Decimal(value))
                else:
                    evm_logs.insert_one({"contract" : tx['txinfo']['to'], "tx" : tx["txinfo"]["hash"], "block" : tx['block'], "status" : "not_enough", "action" : "reverted", "from" : sender, "to": to, "value" : str(value)})
                evm_transactions.insert_one({"rawtx": tx["rawtx"]})
                
        if tx['txinfo']['to'] == "0x4100000000000000000000000000000000000313":
            if tx['txinfo']['data'][0:10] == '0x43489b21':
                sender = tx['txinfo']['sender']
                add_or_update_stake(tx['txinfo']['to'], sender, Decimal(tx['txinfo']['value']), tx['block'])
                evm_logs.insert_one({"contract" : tx['txinfo']['to'], "tx" : tx["txinfo"]["hash"], "block" : tx['block'], "status" : "ok", "action" : "stake", "from" : sender, "to": tx['txinfo']['to'], "value" : str(tx['txinfo']['value'])})
                evm_transactions.insert_one({"rawtx": tx["rawtx"]})
            if tx['txinfo']['data'][0:10] == '0x43489b22':
                sender = tx['txinfo']['sender']
                staked = c_get_stake(tx['txinfo']['to'], sender)
                r = check_elena_balance(tx['txinfo']['to'], staked)
                if r:
                    add_or_update_elena_balance(tx['txinfo']['to'], Decimal(staked)*-1)
                    add_or_update_elena_balance(sender, staked)
                    add_or_update_stake(tx['txinfo']['to'], sender, Decimal(staked)*-1, tx['block'])
                    evm_logs.insert_one({"contract" : tx['txinfo']['to'], "tx" : tx["txinfo"]["hash"], "block" : tx['block'], "status" : "ok", "action" : "unstake", "from" : tx['txinfo']['to'], "to": sender, "value" : str(staked)})
                else:
                    evm_logs.insert_one({"contract" : tx['txinfo']['to'], "tx" : tx["txinfo"]["hash"], "block" : tx['block'], "status" : "not_enough", "action" : "reverted", "from" : tx['txinfo']['to'], "to": sender, "value" : str(staked)})
                    
                evm_transactions.insert_one({"rawtx": tx["rawtx"]})
            if tx['txinfo']['data'][0:10] == '0x43489b23':
                sender = tx['txinfo']['sender']
                reward = get_reward(tx['txinfo']['to'], sender)
                #r = check_balance("0x0000000000000000000000000000000000000041", tx['txinfo']['to'], reward)
                #if r:
                c_add_or_update_balance("0x0000000000000000000000000000000000000041", tx['txinfo']['to'], Decimal(reward)*-1)
                c_add_or_update_balance("0x0000000000000000000000000000000000000041", sender, reward)
                c_add_or_update_reward(tx['txinfo']['to'], sender, Decimal(reward)*-1)
                evm_logs.insert_one({"contract" : tx['txinfo']['to'], "tx" : tx["txinfo"]["hash"], "block" : tx['block'], "status" : "ok", "action" : "claim", "from" : tx['txinfo']['to'], "to": sender, "value" : str(reward)})
                #else:
                #    evm_logs.insert_one({"contract" : tx['txinfo']['to'], "tx" : tx["txinfo"]["hash"], "block" : tx['block'], "status" : "not_enough", "action" : "reverted", "from" : tx['txinfo']['to'], "to": sender, "value" : str(reward)})
                    
                evm_transactions.insert_one({"rawtx": tx["rawtx"]})
                
            agora = evm_contracts.find_one({'address': '0x4100000000000000000000000000000000000313'})
            sts = {}
            totalst = 0
            tactualblock = tx['block']
            if int(tactualblock) > int(agora['currentblock']):
                stakers = evm_memory.find({'contract': '0x4100000000000000000000000000000000000313'})
                
                for s in stakers:
                    if tactualblock < 105000:
                        if int(s['block']) < 61500:
                            totalst += Decimal(Decimal(s['value'])/10000000000000000)
                    else:
                        if int(s['block']) < int(tactualblock) - 43500:
                            totalst += Decimal(Decimal(s['value'])/10000000000000000)
                
                stakers = evm_memory.find({'contract': '0x4100000000000000000000000000000000000313'})
                reward = 1000000000000000 * int(int(tactualblock)-int(agora['currentblock']))
                for s in stakers:
                    if tactualblock < 105000:
                        if int(s['block']) < 61500:
                            rw = math.floor(reward*(Decimal(Decimal(s['value'])/10000000000000000)/totalst))
                            c_add_or_update_reward("0x4100000000000000000000000000000000000313", s['address'], rw)
                    else:
                        if int(s['block']) < int(tactualblock) - 43500:
                            rw = math.floor(reward*(Decimal(Decimal(s['value'])/10000000000000000)/totalst))
                            c_add_or_update_reward("0x4100000000000000000000000000000000000313", s['address'], rw)
                        
                evm_contracts.update_one({"address": "0x4100000000000000000000000000000000000313"}, {"$set": {"currentblock": int(tactualblock)}})
                    
    evm_internal.update_one({"info": "lastscannedblock"}, {"$set": {"value": int(pblock)}})
    print(str(time.time()) + "EVM processed: " + str(txpc) + " transactions")

def socket_monitor_thread(client_thread, server):
    lastc = 0
    slastc = 300
    while True:
        if not client_thread.is_alive():
            lastc = slastc
            slastc = int(time.time())
            client_thread = threading.Thread(target=http_client, args=(server,))
            client_thread.start()
        if lastc + 10 > slastc:
            time.sleep(30)
        else:
            time.sleep(1)

def launch_socket_client(server):
    client_thread = threading.Thread(target=http_client, args=(server,))
    client_thread.daemon = True
    client_thread.start()
    
    m_thread = threading.Thread(target=socket_monitor_thread, args=(client_thread,server,))
    m_thread.daemon = True
    m_thread.start()   

def register_peer(server):
    hdata = "313.01"
    url = "http://" + server + ":9090/registerpeer"
    response = requests.post(url, data=hdata, timeout=5)

def http_client(server):
    global actualblock
    last_id = actualblock
    last_mempool = 0
    mempooltxs = 0
    mempooltimer = random.randint(0, 59)
    while True:
        try:
            t = int(time.time())
            if actualblock != last_id:
                hdata = str(actualblock)
                url = "http://" + server + ":9090/notifyblock"
                response = requests.post(url, data=hdata, timeout=5)
                last_id = actualblock
            if t != last_mempool and t % 60 == int(mempooltimer):
                last_mempool = t
                mempooltxs = 0
                url = "http://" + server + ":9090/getmempool"
                response = requests.get(url, timeout=5)
                data = response.json()
                results = data['result']
                for tx in results:
                    mempooltxs += 1
                    hdata = str(tx['rawtx'])
                    url = "http://localhost:9090/addtransaction"
                    response = requests.post(url, data=hdata, timeout=2)
                if mempooltxs > 0:
                    print("[worker] " + str(int(time.time())) +  " Mempool processed: " + str(mempooltxs) + " txs from " + str(server))
            time.sleep(0.5)
        except Exception as e:
            time.sleep(30)
            return

def rollback_block(height):
    print("[worker] " + str(int(time.time())) + "Rollback block: " + str(height))
    for txn in txs.find({"block": int(height)}):
        tx = Tx(txn['rawtx'])
        add_or_update_balance(tx.txinfo['to'], int(tx.txinfo['value']) * -1)
        if int(txn['type']) > 1:
            add_or_update_balance(tx.txinfo['sender'], str((int(tx.txinfo['value']) + (int(tx.txinfo['gasprice'])*int(tx.txinfo['startgas'])))))
        print("[worker] " + str(int(time.time())) +  " Transacction removed: " + str(int(tx.txinfo['value'])/1000000000000000000) + " ELEN, Hash: " + str(tx.txinfo['hash']))
        logs.delete_many({'hash': tx.txinfo['hash']})
        txs.delete_many({'rawtx': tx.rawtx})
    bkp = blocks.find_one({'height': height})
    backup.insert_one(bkp)
    blocks.delete_many({'height': height})

def check_and_convert(data):
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    return data

def hex_to_bytes(data: str) -> bytes:
    return to_bytes(hexstr=HexStr(data))

def is_valid_tx(raw_transaction):
    if not is_hex(raw_transaction):
        return False
    try:
        tx = rlp.decode(hex_to_bytes(raw_transaction), Transaction)
    except:
        return False
    return True

def add_or_update_balance(account, value):
    account = account.lower()
    balance = balances.find_one({"account": account})
    if balance is None:
        new_balance = {"account": account, "value": str(value)}
        balances.insert_one(new_balance)
    else:
        new_value = int(balance["value"]) + int(value)
        balances.update_one({"account": account}, {"$set": {"value": str(new_value)}})

    return True

def to_byte_array(b):
    return [byte for byte in b]

def pack_nonce(blob, nonce):
    b = binascii.unhexlify(blob)
    bin = struct.pack('39B', *bytearray(b[:39]))
    bin += struct.pack('I', nonce)
    bin += struct.pack('{}B'.format(len(b)-43), *bytearray(b[43:]))
    return bin

def compute_hash(b, n, s, h):
    seed = binascii.unhexlify(s);
    nonce = struct.unpack('I',binascii.unhexlify(n))[0]
    bin = pack_nonce(b, nonce)
    hex_hash = binascii.hexlify( pyrx.get_rx_hash(bin, seed, h) )
    return hex_hash

def sync_blockchain(force, server):
    previous_data = None
    global actualblock
    data = None
    theight = 0
    print("[worker] " + str(int(time.time())) +  " Syncing blockchain...")
    while True:
        z = blocks.find_one(sort=[("height", -1)])
        try:
            height = z['height']+1
            prevhash = z['hash']
        except:
            height = 1
            prevhash = "0000000000000000000000000000000000000000000000000000000000000000"
           
        try:
            timestamp = int(z['timestamp'])
        except:
            timestamp = 0
        
        if force == 0:
            try:
                url = "http://" + server + ":9090/getminingtemplate"
                response = requests.get(url, timeout=5)
                data = response.json()
                theight = data['height']
            except ValueError as e:
                print("[worker] " + str(time.time()) + ", Eleneum server connection error, retrying...");
                print(e)
            except Exception as e:
                print("[worker] " + str(time.time()) + ", Eleneum server connection error, retrying...");
                print(e)
            
        try:
            if (data != previous_data and height < theight) or force == 1:  # Comparar los datos con los previos
                hdata = str(height)
                url = "http://" + server + ":9090/getblocks"
                response = requests.post(url, data=hdata, timeout=5)
                data = response.json()
                results = data['result']
                for block in results:
                    if(prevhash == block['prev_hash'] and timestamp <= int(block['timestamp'])):
                        hblock = Block(block['height'], block['prev_hash'], block['transactions'], block['public_key'], int(block['timestamp']))
                        
                        if 'sign' not in block:
                            block['sign'] = ''
                        
                        hblock.syncblock(block['hash'], block['nonce'], block['extranonce'], block['difficulty'], block['rewardtx'], block['sign'])
                        if len(block['transactions']) > 0:
                            evm(int(block['height']))
                        prevhash = block['hash']
                        actualblock = int(block['height'])
                        
                    else:
                        print("[worker] " + str(int(time.time())) +  " Invalid block found. Height: " + str(block['height']))
                        if height <= block['height'] and prevhash != block['prev_hash']:
                            rollback_block(int(height)-1)
                        break
                print("[worker] " + str(int(time.time())) +  " Block found and inserted. Height: " + str(block['height']))
                previous_data = data
                if force == 1:
                    break
            else:
                actualblock = int(height)-1
                print("[worker] " + str(int(time.time())) +  " Blockchain fully synced. Height: " + str(actualblock))
                break
        except ValueError as e:
            print("[worker] " + str(time.time()) + ", Sync error. Maybe blockchain is fully synced...");
            break
        except Exception as e:
            if force == 0:
                print("[worker] " + str(time.time()) + ", Peer error connection, closing connection..." + str(e))
            else:
                print("[worker] " + str(time.time()) + ", Blockchain fully synced")
            break

class Tx:
    def __init__(self, rawtx):
        self.rawtx = rawtx
        tx = rlp.decode(hex_to_bytes(self.rawtx), Transaction)
        self.txinfo = tx.to_dict()
        self.txinfo['value'] = str(self.txinfo['value'])
        self.txinfo['v'] = str(self.txinfo['v'])
        self.txinfo['r'] = str(self.txinfo['r'])
        self.txinfo['s'] = str(self.txinfo['s'])
        self.txinfo['sender'] = self.txinfo['sender'].lower()
        self.txinfo['to'] = self.txinfo['to'].lower()

    def add_to_mempool(self):
        if self.check_balance():
            if self.check_duplicate():
                return 0
            try:
                mempool.insert_one(self.__dict__)
                return 1
            except Exception as e:
                return -1
        else:
            return json.dumps({'error': 'Insufficient balance.'})

    def check_duplicate(self):
        if mempool.find_one({'rawtx': self.rawtx}):
            return True
        if txs.find_one({'rawtx': self.rawtx}):
            return True
        return False

    def add_to_blockchain(self, checkbalance, block, timestamp):
        if txs.find_one({'rawtx': self.rawtx}):
            return False
        if checkbalance == 1:
            if self.check_balance() == True:
                try:
                    self.block = block
                    self.type = 2
                    self.timestamp = timestamp
                    txs.insert_one(self.__dict__)
                    return True
                except Exception as e:
                    return False
            else:
                return False
        else:
            try:
                self.block = block
                self.type = 1
                self.timestamp = timestamp
                txs.insert_one(self.__dict__)
                return True
            except Exception as e:
                return False
        
    def check_balance(self):
        balance = balances.find_one({"account": self.txinfo['sender']})
        if balance is None:
            new_balance = {"account": self.txinfo['sender'], "value": "0"}
            balances.insert_one(new_balance)
            return False
        else:
            sender_balance = int(balance["value"])
            if sender_balance >= int(self.txinfo['value']) + (int(self.txinfo['gasprice'])*int(self.txinfo['startgas'])):
                return True
            else:
                return False

class Block:
    def __init__(self, height, prev_hash, transactions, public_key, timestamp):
        self.height = height
        self.prev_hash = prev_hash        
        self.timestamp = int(timestamp)
        self.transactions = transactions
        self.rewardtx = None
        self.public_key = public_key
        self.difficulty = self.get_diff()
        self.nonce = None
        self.extranonce = None
        self.version = "0101"

    def get_reward(self):
        if self.height == 1:
            reward = 415800
        else:
            reward = 15 - math.log(100000 + self.height - 1, 10)
            
        if reward < 1:
            reward = 1
            
        return round(reward, 8)
        
    def process_mempool(self):
        processed = 0
        duplicated = 0
        pvalue = 0
        dvalue = 0
        for txn in mempool.find():
            tx = Tx(txn['rawtx'])
            if tx.check_balance() == True:
                rn = tx.add_to_blockchain(1, self.height, self.timestamp)
                if rn == True:
                    self.transactions.append(tx.rawtx)
                    add_or_update_balance(tx.txinfo['to'], tx.txinfo['value'])
                    add_or_update_balance(tx.txinfo['sender'], str((int(tx.txinfo['value']) + (int(tx.txinfo['gasprice'])*int(tx.txinfo['startgas']))) * -1))
                    processed += 1
                    pvalue += int(tx.txinfo['value'])
                    #print("[miner] " + str(int(time.time())) +  " Transacction processed: " + str(int(tx.txinfo['value'])/1000000000000000000) + " ELEN, Hash: " + str(tx.txinfo['hash']))
                    log = {"tx": str(tx.txinfo['hash']), "block": self.height, "status": "ok", "action": "inserted"}
                    logs.insert_one(log)
                else:
                    duplicated += 1
                    dvalue += int(tx.txinfo['value'])
                    #print("[miner] " + str(int(time.time())) +  " Transacction duplicated, Hash: " + str(tx.txinfo['hash']))
                    log = {"tx": str(tx.txinfo['hash']), "block": self.height, "status": "deplicated", "action": "reverted"}
                    logs.insert_one(log)
                mempool.delete_many({'rawtx': tx.rawtx})
        mempool.delete_many({})
        if processed > 0:
            print("[miner] " + str(int(time.time())) +  " Transacction processed: " + str(processed) + ", Total value: " + str(int(pvalue)/1000000000000000000) + " ELENA")
        if duplicated > 0:
            print("[miner] " + str(int(time.time())) +  " Transacction not processed: " + str(duplicated) + ", Total value: " + str(int(dvalue)/1000000000000000000) + " ELENA")

    def get_diff(self):
        offset = 16
        if self.height == 1:
            diff = 0
        elif self.height > offset:
            a = blocks.find(sort=[("height", -1)]).limit(offset)
            dsum = sum(doc["difficulty"] for doc in a)
            dsum = math.ceil(dsum / offset)
            z = blocks.find(sort=[("height", -1)]).limit(offset)
            t = abs(z[offset-1]["timestamp"] - z[0]["timestamp"])
            blocktime = 20
            
            if t != 0:
                diff = math.ceil((dsum*offset*blocktime)/t)
            else:
                diff = 25000000
        else:
            diff = 25000000
        return diff
        
    def get_seed(self):
        if(math.floor(self.height/1024) == 0):
            seed = "0000000000000000000000000000000000000000000000000000000000000313"
        else:
            seed = "0000000000000000000000000000000000000000000000000000000000000313"
        return seed
    
    def get_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        h = hashlib.sha512(block_string.encode())
        hash_hex = h.hexdigest()
        return hash_hex[:64]

    def create_reward_transaction(self):
        txnonce = self.height
        txvalue = w3.to_wei(self.get_reward(), 'ether')
        tx = {
            'nonce': txnonce,
            'to': self.public_key,
            'value': txvalue,
            'gas': 1,
            'gasPrice': w3.to_wei('0', 'gwei')
        }
        signed_tx = w3.eth.account.sign_transaction(tx, sender_private_key)
        signedtx = signed_tx.hash.hex()[2:]
        self.rewardtx = signed_tx.rawTransaction.hex()
        return signedtx

    def get_blob(self):
        seed = self.get_seed()
        seed = binascii.unhexlify(seed);
        hdiff = hex(self.difficulty)[2:].zfill(10)
        rewardhash = self.create_reward_transaction()
        blob = "0000" + self.prev_hash + hdiff + "00000000" + rewardhash
        return blob
        
    def syncblock(self, blockhash, nonce, extranonce, difficulty, rewardtx, sign):
        processed = 0
        duplicated = 0
        pvalue = 0
        dvalue = 0
        
        self.nonce = nonce
        self.extranonce = extranonce
        self.rewardtx = rewardtx
        self.sign = sign
        
        if int(self.get_diff()) == int(difficulty):
            self.difficulty = difficulty
        else:
            print("[miner] " + str(int(time.time())) +  " Invalid block difficulty, can't sync with this blockchain")
            return

        rwtxa = Tx(self.rewardtx)
        expectedreward = w3.to_wei(self.get_reward(), 'ether')
        if int(rwtxa.txinfo['value']) != int(expectedreward):
            print("[miner] " + str(int(time.time())) +  " Invalid reward value, can't sync with this blockchain")
            return
            
        if self.sign_verify == False:
            print("[miner] " + str(int(time.time())) +  " Invalid block signature, can't sync with this blockchain")
            return
        
        seed = self.get_seed()
        hdiff = hex(self.difficulty)[2:].zfill(10)
        rewardhash = rwtxa.txinfo['hash'][2:]
        blob = self.extranonce + self.prev_hash + hdiff + "00000000" + rewardhash
        hex_hash = compute_hash(blob, nonce, seed, self.height)
        hash_bytes = bytes.fromhex(hex_hash.decode())
        hash_array = to_byte_array(hash_bytes)[::-1]
        hash_num = int.from_bytes(bytes(hash_array), byteorder='big')
        hash_diff = base_diff / hash_num
        if hash_diff < self.difficulty:
            print("[miner] " + str(int(time.time())) +  " Invalid nonce, block difficulty too low, can't sync with this blockchain")
            return

        rwtxn = rwtxa.add_to_blockchain(0, self.height, self.timestamp)
        add_or_update_balance(self.public_key, str(w3.to_wei(self.get_reward(), 'ether')))
        self.hash = blockhash
        for txn in self.transactions:
            tx = Tx(txn)
            if tx.check_balance() == True:
                rn = tx.add_to_blockchain(1, self.height, self.timestamp)
                if rn == True:
                    add_or_update_balance(tx.txinfo['to'], tx.txinfo['value'])
                    add_or_update_balance(tx.txinfo['sender'], str((int(tx.txinfo['value']) + (int(tx.txinfo['gasprice'])*int(tx.txinfo['startgas']))) * -1))
                    #print("[miner] " + str(int(time.time())) +  " Transacction processed: " + str(int(tx.txinfo['value'])/1000000000000000000) + " ELEN, Hash: " + str(tx.txinfo['hash']))
                    processed += 1
                    pvalue += int(tx.txinfo['value'])
                    log = {"tx": str(tx.txinfo['hash']), "block": self.height, "status": "ok", "action": "inserted"}
                    logs.insert_one(log)
                else:
                    #print("[miner] " + str(int(time.time())) +  " Transacction duplicated, Hash: " + str(tx.txinfo['hash']))
                    duplicated += 1
                    dvalue += int(tx.txinfo['value'])
                    log = {"tx": str(tx.txinfo['hash']), "block": self.height, "status": "deplicated", "action": "reverted"}
                    logs.insert_one(log)
                mempool.delete_many({'rawtx': tx.rawtx})
        if processed > 0:
            print("[miner] " + str(int(time.time())) +  " Transacction processed: " + str(processed) + ", Total value: " + str(int(pvalue)/1000000000000000000) + " ELENA")
        if duplicated > 0:
            print("[miner] " + str(int(time.time())) +  " Transacction not processed: " + str(duplicated) + ", Total value: " + str(int(dvalue)/1000000000000000000) + " ELENA")

        self.add_to_db()

    def mine(self, nonce, extranonce):
        self.nonce = nonce
        self.extranonce = extranonce
        seed = self.get_seed()
        hdiff = hex(self.difficulty)[2:].zfill(10)
        rewardhash = self.create_reward_transaction()
        blob = self.extranonce + self.prev_hash + hdiff + "00000000" + rewardhash
        hex_hash = compute_hash(blob, nonce, seed, self.height)
        hash_bytes = bytes.fromhex(hex_hash.decode())
        hash_array = to_byte_array(hash_bytes)[::-1]
        hash_num = int.from_bytes(bytes(hash_array), byteorder='big')
        hash_diff = base_diff / hash_num
        if hash_diff >= self.difficulty:
            self.process_mempool()
            rwtxa = Tx(self.rewardtx)
            rwtxn = rwtxa.add_to_blockchain(0, self.height, self.timestamp)
            block_hash = self.get_hash()
            self.hash = block_hash
            self.sign_block()
            self.add_to_db()
            add_or_update_balance(self.public_key, str(w3.to_wei(self.get_reward(), 'ether')))
            return True
        else:
            return False

    def sign_block(self):
        try:
            block_string = json.dumps(self.__dict__, sort_keys=True)
            block_hash = hashlib.sha3_256(block_string.encode()).hexdigest()
            message = messages.encode_defunct(hexstr=block_hash)
            signed_block = Account.sign_message(message, private_key=sender_private_key)
            self.sign = signed_block.signature.hex()
        except Exception as e:
            print(e)
            traceback.print_exc()

    def sign_verify(self):
        try:
            pkey = self.public_key
            signature_hash = self.sign
            try:
                del self.sign
            except:
                pass
            try:
                del self._id
            except:
                pass
            print(signature_hash)
            block_string = json.dumps(self.__dict__, sort_keys=True)
            block_hash = hashlib.sha3_256(block_string.encode()).hexdigest()
            message = messages.encode_defunct(hexstr=block_hash)
            is_valid = Account.recover_message(message, signature=signature_hash) == pkey
            if is_valid:
                self.sign = signature_hash
            return is_valid
        except Exception as e:
            print(e)
            traceback.print_exc()

    def add_to_db(self):
        blocks.insert_one(self.__dict__)

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()


    def do_GET(self):
        global actualblock
        if str(self.path) == "/gettopblock":
            self._set_response()
            resp = '{"version": "1.0", "height": ' + str(actualblock) + '}'
            self.wfile.write(resp.encode('utf-8'))
        if str(self.path) == "/getmempool":
            self._set_response()
            results = mempool.find()
            result_list = []
            for result in results:
                result_list.append(result)
            json_output = json.loads(json_util.dumps({"id": 1, "status": "ok", "result": result_list}))
            self.wfile.write(json.dumps(json_output).encode('utf-8'))
        if str(self.path) == "/getminingtemplate":
            z = blocks.find_one(sort=[("height", -1)])
            try:
                height = z['height']+1
                prevhash = z['hash']
            except:
                height = 1   
                prevhash = "0000000000000000000000000000000000000000000000000000000000000000"
                
            try:
                timestamp = int(z['timestamp'])+1
            except:
                timestamp = int(time.time())
            self._set_response()
            transactions = []
            block = Block(height, prevhash, transactions, sender_address, int(datetime.datetime.now().timestamp()))
            blob = block.get_blob()
            seed = block.get_seed()
            resp = '{"version": "1.0", "difficulty": ' + str(block.difficulty) + ', "blob": "' + blob + '", "seed": "' + seed + '", "height": ' + str(block.height) + '}'
            self.wfile.write(resp.encode('utf-8'))

    def do_POST(self):
        global actualblock
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        if str(self.path) == "/registerpeer":
            post_data = post_data.decode('utf-8')
            self._set_response()
            self.wfile.write("{status: 'ok'}".encode('utf-8'))
            if post_data == "313.01":
                data = {
                    'ip': str(self.client_address[0]),
                    'port': '9090',
                    'status': 'ok'
                }
                mfilter = {'ip': str(self.client_address[0])}
                peers.update_one(mfilter, {'$set': data}, upsert=True)
        if str(self.path) == "/notifyblock":
            post_data = post_data.decode('utf-8')
            block = int(post_data)
            self._set_response()
            self.wfile.write("{status: 'ok'}".encode('utf-8'))
            if actualblock < block:
                sync_blockchain(1, self.client_address[0])
        if str(self.path) == "/syncbc":
            post_data = post_data.decode('utf-8')
            self._set_response()
            self.wfile.write("{status: 'ok'}".encode('utf-8'))
            sync_blockchain(1, post_data)
        if str(self.path) == "/getblocks":
            post_data = post_data.decode('utf-8')
            self._set_response()
            results = blocks.find({"height": {"$gte": int(post_data)}}).limit(200)
            result_list = []
            for result in results:
                result_list.append(result)
            json_output = json.loads(json_util.dumps({"id": 1, "status": "ok", "result": result_list}))
            self.wfile.write(json.dumps(json_output).encode('utf-8'))
        if str(self.path) == "/mineblock":
            z = blocks.find_one(sort=[("height", -1)])
            try:
                height = z['height']+1
                prevhash = z['hash']
            except:
                height = 1
                prevhash = "0000000000000000000000000000000000000000000000000000000000000000"
            try:
                timestamp = int(z['timestamp'])+1
            except:
                timestamp = int(time.time())
            self._set_response()
            post_data = post_data.decode('utf-8')
            transactions = []
            block = Block(height, prevhash, transactions, sender_address, datetime.datetime.now().timestamp())
            extranonce = post_data[:4]
            nonce = post_data[-8:]
            rt = block.mine(nonce, extranonce)
            if rt == True:
                actualblock = block.height
                self.wfile.write(('{"status": "ok", "hash": "' + str(block.hash) + '", "difficulty": "' + str(block.difficulty) + '", "height": "' + str(block.height) + '"}').encode('utf-8'))
                print("[miner] " + str(int(time.time())) +  " New block found! Height:  " + str(block.height) + ", Difficulty: " + str(block.difficulty) + ", Extranonce: " + str(block.extranonce) + ", Nonce: " + str(block.nonce))
                if len(block.transactions) > 0:
                    evm(int(block.height))
            else:
                self.wfile.write('{"status": "error"}'.encode('utf-8'))
        if str(self.path) == "/addtransaction":
            self._set_response()
            post_data = post_data.decode('utf-8')
            tx = Tx(post_data)
            n = is_valid_tx(post_data)
            if n == True:
                rn = tx.add_to_mempool()
                if rn == 1:
                    self.wfile.write(('{"status": "ok", "hash" : "' + str(tx.txinfo['hash']) + '"}').encode('utf-8'))
                elif rn == -1:
                    self.wfile.write('{"status": "error"}'.encode('utf-8'))
                elif rn == 0:
                    self.wfile.write(('{"status": "ok", "hash" : "' + str(tx.txinfo['hash']) + '"}').encode('utf-8'))
            else:
                self.wfile.write('{"status": "error"}'.encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=9090):
    logging.basicConfig(level=logging.WARNING)
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    print("[worker] " + str(int(time.time())) + 'Starting httpd...')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("[worker] " + str(int(time.time())) +  'Stopping httpd...')

def eleneum_start():
    create_indexes(blocks, indices_blocks)
    create_indexes(txs, indices_transactions)

    load_config('eleneum.json')

    sync_blockchain(0, "eleneum.org")
    
    http_monitor = threading.Thread(target=peer_monitor)
    http_monitor.daemon = True
    http_monitor.start()
    
    try:
        register_peer("elena.onlyapool.online")
        register_peer("elena.yourmining.site")
        register_peer("pool.eleneum.org")
        register_peer("eleneum.org")
    except Exception as e:
        print(e)
    
    run()

eleneum_start()
