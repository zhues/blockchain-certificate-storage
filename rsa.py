import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


# 获取新的密钥对
def getKeyPair():
    key_ = RSA.generate(2048)
    priv_key = key_.export_key()
    pub_key = key_.publickey().export_key()
    return priv_key, pub_key


# 查看是否生成了rsa公私钥，没有则生成公私钥文件
def genRsaKeys():
    if not os.path.exists("./Keys"):
        print("生成节点公私钥目录，生成公私钥")
        os.mkdir("Keys")
        for i in range(0, 5):
            if not os.path.exists("./Keys/N"+str(i)):
                os.mkdir("./Keys/N"+str(i))
            (priv, pub) = getKeyPair()
            privFileName = "Keys/N"+str(i)+"/N"+str(i)+"_RSA_PIV"
            file = open(privFileName, "wb")
            file.write(priv)
            file.close()

            pubFileName = "Keys/N"+str(i)+"/N"+str(i)+"_RSA_PUB"
            file2 = open(pubFileName, "wb")
            file2.write(pub)
        print("完成公私钥生成")


# rsa签名
def RsaSignWithSha256(priv_key, data):
    private_key = RSA.importKey(priv_key)
    digest = SHA256.new(data.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(digest)
    sign = base64.b64encode(signature)
    sign = sign.decode()
    return sign


# 验证签名
def RsaVerySignWithSha256(data, signdata, pub_key):
    public_key = RSA.importKey(pub_key)
    digest = SHA256.new(data.encode('utf-8'))
    sign = signdata.encode()
    sign = base64.b64decode(sign)
    try:
        pkcs1_15.new(public_key).verify(digest, sign)
        return 1
    except:
        return 0


# 验证签名
def RsaVerySignWithHash(data, signdata, pub_key):
    public_key = RSA.importKey(pub_key)
    sign = signdata.encode()
    sign = base64.b64decode(sign)
    try:
        pkcs1_15.new(public_key).verify(data, sign)
        return 1
    except:
        return 0
