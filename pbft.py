import rsa
import json
from time import time
from uuid import uuid4
from flask import Flask, jsonify, request
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from socket import *
import BlockChain
import hashlib
import threading


nodeCount = 5
data_pool = []
mutex = threading.Lock()
global blockchain_ret


def getDigest(r):
    data = json.dumps(r)
    r_hash = SHA256.new(data.encode("utf-8"))
    return r_hash


def getPubKey(nodeID):
    privFileName = "Keys/N" + str(nodeID) + "/N" + str(nodeID) + "_RSA_PUB"
    file = open(privFileName, "r")
    pubkey = file.read().encode()
    return pubkey


def getPrivKey(nodeID):
    privFileName = "Keys/N" + str(nodeID) + "/N" + str(nodeID) + "_RSA_PIV"
    file = open(privFileName, "r")
    privkey = file.read().encode()
    return privkey


def getSignPubKey(sign_curr):
    privFileName = "Keys/sign" + str(sign_curr) + "/" + str(sign_curr) + "_RSA_PUB"
    file = open(privFileName, "r")
    pubkey = file.read().encode()
    return pubkey


# 参与共识的节点属性和操作函数
class Pbft(object):
    class Node(object):
        pass

    def __init__(self, nodeID, blockchain):
        self.nodeID = nodeID
        self.rsaPrivKey = getPrivKey(self.nodeID)
        self.rsaPubKey = getPubKey(self.nodeID)
        self.lock = threading.Lock
        self.sequenceID = 0
        self.messagePool = {}
        self.prePareConfirmCount = {}
        self.commitConfirmCount = {}
        self.isCommitBordcast = {}
        self.isReply = {}
        self.block_chain = blockchain

    def sequenceIDAdd(self):
        self.sequenceID += 1

    # 根据指令，判断到达哪个阶段
    def handleRequest(self, cmd, data, blockchain, s):
        match cmd:
            case 1:
                # cRequest
                return self.handleClientRequest(data, blockchain, s)
            case 2:
                # cPrePrepare
                return self.handlePrePrepare(data, blockchain, s)
            case 3:
                # cPrepare
                return self.handlePrepare(data, blockchain, s)
            case 4:
                # cCommit
                return self.handleCommit(data, blockchain, s)

    # 主节点处理客户端信息，验证区块中签章人信息，签名是否正确，验证后添加签名，并发送给矿工节点
    # 待添加：主节点查询文档上一块高，签章人上一块高
    def handleClientRequest(self, data, blockchain, s):
        r = json.loads(data)
        r['index'] = self.block_chain.chain[-1]['index'] + 1
        r['previous_hash'] = self.block_chain.hash(r['index']-2)
        self.sequenceIDAdd()
        j = 0
        if self.nodeID == 0:
            print("签名验证", time())
        for i in r['transactions']:
            document_hash = i["document_hash"]
            last_docu_height = self.block_chain.FindBlockWithDocument(i["document_name"])
            i['last_docu_height'] = last_docu_height
            if last_docu_height != 1 and i['sign_curr'] and i['sign_curr'] != self.block_chain.chain[last_docu_height-1]['transactions'][j]['sign_next'] and self.block_chain.chain[last_docu_height-1]['transactions'][j]['sign_next'] != -1:
                print(i['sign_curr'])
                print(self.block_chain.chain[last_docu_height-1]['transactions'][j]['sign_next'])
                print("签章人员错误")
                return 0, self.block_chain.chain[-1]['index']
            if i['sign_curr']:
                last_sign_height = self.block_chain.FindBlockWithSign(i["sign_curr"])
                i['last_sign_height'] = last_sign_height
                sign_curr = i["sign_curr"]
                signature = i["signature"]
                sign_pubkey = getSignPubKey(sign_curr)
                if not rsa.RsaVerySignWithSha256(document_hash, signature, sign_pubkey):
                    print("文档签名信息错误")
                    return 0, self.block_chain.chain[-1]['index']
            else:
                i['last_sign_height'] = 1
            j += 1

        if self.nodeID == 0:
            print("签名验证", time())
        r_string = json.dumps(r).encode()
        digest = hashlib.sha256(r_string).hexdigest()
        self.messagePool[digest] = r
        data1 = json.dumps(r)
        signInfo = rsa.RsaSignWithSha256(self.rsaPrivKey, data1)
        Pre_Prepare = {
            "data": r,
            "digest": digest,
            "sequenceID": self.sequenceID,
            "signInfo": signInfo,
        }
        cPrePrepare = 2
        pp_data = json.dumps(Pre_Prepare)
        send_data = {
            'cmd': cPrePrepare,
            'content': pp_data
        }
        self.broadcast(send_data, s)
        return 1, self.block_chain.chain[-1]['index']

    # 矿工节点验证消息签名、主节点签名、消息摘要、消息序号等信息，添加自己签名，
    def handlePrePrepare(self, data, blockchain, s):
        if self.nodeID == 0:
            print("共识时间", time())
        pp = json.loads(data)
        primaryNodePubKey = getPubKey(0)
        data_string = json.dumps(pp["data"]).encode()
        digest = hashlib.sha256(data_string).hexdigest()
        pp_data = json.dumps(pp["data"])
        if digest != pp["digest"]:
            print("消息摘要错误")
            return 0, self.block_chain.chain[-1]['index']
        elif self.sequenceID+1 != pp["sequenceID"] and self.nodeID != 0:
            print("消息序号错误")
            return 0, self.block_chain.chain[-1]['index']
        elif not rsa.RsaVerySignWithSha256(pp_data, pp["signInfo"], primaryNodePubKey):
            print("主节点签名验证错误")
            return 0, self.block_chain.chain[-1]['index']
        else:
            self.sequenceID = pp["sequenceID"]
            self.messagePool[pp["digest"]] = pp["data"]
            sign = rsa.RsaSignWithSha256(self.rsaPrivKey, digest)
            pre = {
                "digest": digest,
                "sequenceID": pp["sequenceID"],
                "nodeID": self.nodeID,
                "sign": sign,
            }
            cPrepare = 3
            pre_data = json.dumps(pre)
            send_data = {
                'cmd': cPrepare,
                'content': pre_data
            }
            self.broadcast(send_data, s)
        return 1, self.block_chain.chain[-1]['index']

    # 各矿工节点验证签名，收集到足够签名后，添加确认信息，将确认信息广播
    def handlePrepare(self, data, blockchain, s):
        pre = json.loads(data)
        MessageNodePubKey = getPubKey(pre["nodeID"])
        if not pre["digest"] in self.messagePool.keys():
            print("无此消息摘要")
            return 2, self.block_chain.chain[-1]['index']
        elif self.sequenceID != pre["sequenceID"] and self.nodeID !=0 :
            print("消息序号错误")
            return 2, self.block_chain.chain[-1]['index']
        elif not rsa.RsaVerySignWithSha256(pre["digest"], pre["sign"], MessageNodePubKey):
            print("节点签名验证失败")
            return 2, self.block_chain.chain[-1]['index']
        else:
            if pre["digest"] not in self.prePareConfirmCount:
                self.prePareConfirmCount[pre["digest"]] = {}
            self.prePareConfirmCount[pre["digest"]][pre["nodeID"]] = 1
            count = 0
            for i in range(0, len(self.prePareConfirmCount[pre["digest"]])):
                count += 1
            if self.nodeID == 0:
                specifiedCount = nodeCount / 3 * 2
            else:
                specifiedCount = int(nodeCount / 3 * 2 + 1)
            if count >= specifiedCount and pre["digest"] not in self.isCommitBordcast:
                print("收到足够数量节点的准备信息")
                sign = rsa.RsaSignWithSha256(self.rsaPrivKey, pre["digest"])
                c = {
                    "digest": pre["digest"],
                    "sequenceID": pre["sequenceID"],
                    "nodeID": self.nodeID,
                    "sign": sign
                }
                cCommit = 4
                c = json.dumps(c)
                send_data = {
                    'cmd': cCommit,
                    'content': c
                }
                self.broadcast(send_data, s)
                self.isCommitBordcast[pre["digest"]] = 1
        return 1, self.block_chain.chain[-1]['index']

    # 各节点收到足够确认信息并验证后，将消息存入本地，主节点将消息上链
    def handleCommit(self, data, blockchain, s):
        c = json.loads(data)
        MessageNodePubKey = getPubKey(c["nodeID"])
        if c["digest"] not in self.prePareConfirmCount:
            print("无此消息摘要，消息错误")
            return 2, self.block_chain.chain[-1]['index']
        elif self.sequenceID != c["sequenceID"] and self.nodeID != 0:
            print("消息序号错误")
            return 2, self.block_chain.chain[-1]['index']
        elif rsa.RsaVerySignWithHash(c["digest"], c["sign"], MessageNodePubKey):
            print("节点签名验证失败")
            return 2, self.block_chain.chain[-1]['index']
        else:
            if c["digest"] not in self.commitConfirmCount:
                self.commitConfirmCount[c["digest"]] = {}
            self.commitConfirmCount[c["digest"]][c["nodeID"]] = 1
            count = 0
            for i in range(0, len(self.commitConfirmCount[c["digest"]])):
                count += 1
            if count >= nodeCount/3*2 and c["digest"] not in self.isReply and c["digest"] in self.isCommitBordcast:
                if self.nodeID == 0:
                    print('成功上链')
                    print("共识时间", time())
                write_data = json.dumps(self.messagePool[c["digest"]])
                write_data = write_data.encode()
                localMessageWrite(write_data, self.nodeID)
                self.block_chain.chain.append(self.messagePool[c['digest']])
                self.isReply[c["digest"]] = 1
        return 3, self.block_chain.chain[-1]['index']

    # 接收消息
    def receive(self, s, i):
        while 1:
            data, address = s.recvfrom(4096 * 2, )
            mutex.acquire()
            data_pool.append(data)
            mutex.release()

    # 处理消息
    def data_handle(self, s, blockchain):
        while 1:
            if len(data_pool):
                mutex.acquire()
                data = data_pool.pop(0)
                mutex.release()
                data = data.decode('utf-8')
                data = json.loads(data)
                ret, index = self.handleRequest(data['cmd'], data['content'], blockchain, s)
                if ret == 3 and self.nodeID == 0 and index == 100:
                    time_start = time()
                    ret_block = self.block_chain.FindAllWithDocumentAndIndex('docu1')
                    time_finish = time()
                    print('%.7f' % (time_finish-time_start))
                    print(ret_block)

    def ClientReceive(self, nodeID, blockchain):
        receive_address = ('127.0.0.'+str(nodeID+1), 7000)
        s = socket(AF_INET, SOCK_DGRAM)
        s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        # 绑定本地ip地址和端口
        s.bind(receive_address)
        print("节点", nodeID, "开始运行")
        i = 0
        # 接收消息
        t1 = threading.Thread(target=self.receive, args=(s, i))
        t2 = threading.Thread(target=self.data_handle, args=(s, blockchain))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # while 1:
        #     data, address = s.recvfrom(4096*2)
        #     if not data:
        #         break
        #     data = data.decode('utf-8')
        #     data = json.loads(data)
        #     p.handleRequest(data['cmd'], data['content'], blockchain, s)

        # 关闭socket
        s.close()

    def broadcast(self, data, s):
        address = ('255.255.255.255', 7000)
        data = json.dumps(data)
        data = data.encode('utf-8')
        s.sendto(data, address)


def ClientInit():
    s = socket(AF_INET, SOCK_DGRAM)
    s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    return s


def ClientSend(s, block):
    address = ('127.0.0.1', 7000)
    data = json.dumps(block)
    send_data = {
        'cmd': 1,
        'content': data
    }
    send_data = json.dumps(send_data)
    send_data = send_data.encode('utf-8')
    s.sendto(send_data, address)


def localMessageWrite(data, nodeID):
    privFileName = "Data/N" + str(nodeID) + "_data"
    file = open(privFileName, "ab")
    file.write(data)
    file.close()
