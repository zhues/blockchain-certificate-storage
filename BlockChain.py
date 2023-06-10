import rsa
import hashlib
import json
from time import time
from uuid import uuid4
from flask import Flask, jsonify, request
import threading
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class Blockchain(object):
    # 区块链初始化
    def __init__(self):
        self.chain = []  # 此列表表示区块链对象本身。
        self.currentTransaction = []  # 此列表用于记录目前在区块链网络中已经经矿工确认合法的交易信息，等待写入新区块中的交易信息。
        self.nodes = set()  # 建立一个无序元素集合。此集合用于存储区块链网络中已发现的所有节点信息
        # Create the genesis block(创建创世区块)
        block0 = self.new_block(previous_hash=1)
        self.chain.append(block0)

    # 创建新区块
    def new_block(self, previous_hash=None):
        # Creates a new Block and adds it to the chain(创建一个新的区块，并将其加入到链中)
        """
        生成新块
        :param previous_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
         """
        block = {
            'index': len(self.chain) + 1,  # 区块编号
            'timestamp': time(),  # 时间戳
            'transactions': self.currentTransaction,  # 交易信息
            'previous_hash': previous_hash or self.hash(self.chain[-1])  # 前一个区块的哈希值
        }

        # Reset the current list of transactions(重置当前事务列表)
        '''
        因为已经将待处理（等待写入下一下新创建的区块中）交易信息列表（变量是：transactions）
        中的所有交易信息写入了区块并添加到区块链末尾，则此处清除此列表中的内容'
        '''
        self.currentTransaction = []
        return block

    # 创建新交易
    def new_transaction(self, transaction):
        # Adds a new transaction to the list of transactions(向交易列表中添加一个新的交易)
        """
                生成新交易信息，此交易信息将加入到下一个待挖的区块中
                :param transaction 新交易 ,文档信息
                :return: The index of the Block that will hold this transaction # 需要将交易记录在下一个区块中
        """
        self.currentTransaction.append(transaction)

        # 下一个待挖的区块中
        return self.last_block['index'] + 1

    def FindBlockWithDocument(self, document_name):
        i = 0
        while i < len(self.chain):
            for j in self.chain[-1-i]['transactions']:
                if j['document_name'] == document_name:
                    return self.chain[-1-i]['index']
            i += 1
        return 1

    def FindBlockWithSign(self, sign_curr):
        i = 0
        while i < len(self.chain):
            for j in self.chain[-1-i]['transactions']:
                if j['sign_curr'] == sign_curr:
                    return self.chain[-1-i]['index']
            i += 1
        return 1

    def FindAllWithSign(self, sign_curr):
        i = 0
        ret = []
        while i < len(self.chain):
            for j in self.chain[-1 - i]['transactions']:
                if j['sign_curr'] == sign_curr:
                    ret.append(self.chain[-1-i])
                    break
            i += 1
        return ret

    def FindAllWithDocument(self, document_name):
        i = 0
        ret = []
        while i < len(self.chain):
            for j in self.chain[-1-i]['transactions']:
                if j['document_name'] == document_name:
                    ret.append(self.chain[-1-i])
                    break
            i += 1
        return ret

    def FindAllWithDocumentAndIndex(self, document_name):
        ret = []
        index = self.FindBlockWithDocument(document_name)
        ret.append(self.chain[index-1])
        while index != 1:
            index = self.chain[index-1]['transactions'][0]['last_docu_height']
            ret.append(self.chain[index-1])
        return ret

    def FindAllWithSignAndIndex(self, sign_curr):
        ret = []
        index = self.FindBlockWithSign(sign_curr)
        ret.append(self.chain[index-1])
        while index != 1:
            index = self.chain[index-1]['transactions'][0]['last_sign_height']
            ret.append(self.chain[index-1])
        return ret

    @staticmethod
    def hash(block):
        # 根据一个区块 来生成这个区块的哈希值（散列值）
        """
               生成块的 SHA-256 hash值
               :param block: <dict> Block
               :return: <str>
               转化为json编码格式之后hash，最后以16进制的形式输出
         """

        # 我们必须确保字典是有序的，否则我们会有不一致的哈希值，sort_keys=True指明了要进行排序
        '''
        首先通过json.dumps方法将一个区块打散，并进行排序（保证每一次对于同一个区块都是同样的排序）
        这个时候区块被转换成了一个json字符串（不知道怎么描述）
        然后，通过json字符串的encode()方法进行编码处理。
        其中encode方法有两个可选形参，第一个是编码描述字符串，另一个是预定义错误信息
        默认情况下，编码描述字符串参数就是：默认编码为 'utf-8'。此处就是默认编码为'utf-8'
        '''
        block_string = json.dumps(block, sort_keys=True).encode()
        # hexdigest(…)以16进制的形式输出
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]  # 区块链的最后一个区块


blockchain = Blockchain()
