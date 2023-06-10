import base64
import hashlib
import json
from time import time, sleep
from uuid import uuid4
from flask import Flask, jsonify, request
import BlockChain
import pbft
import rsa
import multiprocessing as mp
import os
import random


# 实例化我们的节点；加载 Flask 框架
app = Flask(__name__)

# 实例化 Blockchain 类
blockchain = BlockChain.Blockchain()

rsa.genRsaKeys()


def node0(nodeID, block_chain):
    p0.ClientReceive(nodeID, block_chain)


def node1(nodeID, block_chain):
    p1.ClientReceive(nodeID, block_chain)


def node2(nodeID, block_chain):
    p2.ClientReceive(nodeID, block_chain)


def node3(nodeID, block_chain):
    p3.ClientReceive(nodeID, block_chain)


def node4(nodeID, block_chain):
    p4.ClientReceive(nodeID, block_chain)


def client():
    newtransaction(5, 1, 5)


p0 = pbft.Pbft(nodeID=0, blockchain=blockchain)
p1 = pbft.Pbft(nodeID=1, blockchain=blockchain)
p2 = pbft.Pbft(nodeID=2, blockchain=blockchain)
p3 = pbft.Pbft(nodeID=3, blockchain=blockchain)
p4 = pbft.Pbft(nodeID=4, blockchain=blockchain)


def document_transaction(docu_ID, sign_no, sign_time, max_time):

    FileName = "document/docu" + str(docu_ID) + "/" + str(sign_time)
    if not os.path.exists("document/docu" + str(docu_ID)):
        os.mkdir("document/docu" + str(docu_ID))
        file = open(FileName, 'wb')
        file.write(b'dauhaodgnsidougnroghner')
        file.close()
    file = open(FileName, 'r')
    data = file.read().encode()
    data = hashlib.sha256(data).hexdigest()
    if not os.path.exists("./Keys/sign" + str(sign_no)):
        os.mkdir("./Keys/" + "sign" + str(sign_no))
        priv, pub = rsa.getKeyPair()
        privFileName = "Keys/sign" + str(sign_no) + "/" + str(sign_no) + "_RSA_PRIV"
        pubFileName = "Keys/sign" + str(sign_no) + "/" + str(sign_no) + "_RSA_PUB"
        file = open(privFileName, "wb")
        file.write(priv)
        file = open(pubFileName, "wb")
        file.write(pub)
        file.close()
    else:
        privFileName = "Keys/sign" + str(sign_no) + "/" + str(sign_no) + "_RSA_PRIV"
        file = open(privFileName, "r")
        priv = file.read().encode()
    sign = rsa.RsaSignWithSha256(priv, data)
    FileName_new = "document/docu" + str(docu_ID) + '/' + str(sign_time+1)
    file1 = open(FileName_new, 'wb')
    write_data = data + sign
    file1.write(write_data.encode())
    file1.close()
    print("生成交易", time())
    if sign_no < max_time:
        transaction_new = {
            'document_hash': data,
            'document_name': 'docu' + str(docu_ID),
            'signature': sign,
            'sign_curr': sign_no,
            'sign_next': sign_no + 1,
            'last_docu_height': 1,
            'last_sign_height': 1,
        }
    else:
        transaction_new = {
            'document_hash': data,
            'document_name': 'docu' + str(docu_ID),
            'signature': sign,
            'sign_curr': sign_no,
            'sign_next': -1,
            'last_docu_height': 1,
            'last_sign_height': 1,
        }
    print("生成交易", time())
    return transaction_new


def newtransaction(sign_num, tran_num, max_time):
    transaction = []
    tran_num_now = 0
    docu = []
    while tran_num_now < tran_num:
        docu_ID = random.randint(0, len(docu))
        if docu_ID == len(docu):
            docu_new = {
                'sign_time': 0,
                'sign_no': 0
            }
            docu.append(docu_new)
            transaction_new = document_transaction(docu_ID, docu[docu_ID]['sign_no'], docu[docu_ID]['sign_time'], max_time)
            docu[docu_ID]['sign_no'] += 1
            docu[docu_ID]['sign_time'] += 1
            transaction.append(transaction_new)
            tran_num_now += 1
        elif docu[docu_ID]['sign_time'] <= max_time:
            transaction_new = document_transaction(docu_ID, docu[docu_ID]['sign_no'], docu[docu_ID]['sign_time'], max_time)
            docu[docu_ID]['sign_no'] += 1
            docu[docu_ID]['sign_time'] += 1
            transaction.append(transaction_new)
            tran_num_now += 1

    # 创建新交易
    for i in range(0, len(transaction)):
        tran = transaction.pop(0)
        blockchain.new_transaction(tran)
        newblock()
        sleep(0.3)


def newblock():
    s = pbft.ClientInit()
    block = blockchain.new_block()
    pbft.ClientSend(s, block)


# 创建 /chain 端点，它是用来返回整个 Blockchain类
@app.route('/chain', methods=['GET'])
# 将返回本节点存储的区块链条的完整信息和长度信息。
def full_chain():
    response = {
        'chain': p0.block_chain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


if __name__ == '__main__':
    pro0 = mp.Process(target=node0, args=(0, blockchain))
    pro1 = mp.Process(target=node1, args=(1, blockchain))
    pro2 = mp.Process(target=node2, args=(2, blockchain))
    pro3 = mp.Process(target=node3, args=(3, blockchain))
    pro4 = mp.Process(target=node4, args=(4, blockchain))
    print(blockchain.chain[0])
    pro_client = mp.Process(target=client)

    pro0.start()
    pro1.start()
    pro2.start()
    pro3.start()
    pro4.start()
    pro_client.start()

    pro0.join()
    pro1.join()
    pro2.join()
    pro3.join()
    pro4.join()
    pro_client.join()

