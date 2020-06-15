import base64

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


secret_key = "u9Qd9wV0Z6Ho9_TzCYyVW_WwBJwL7KvSl4k8fmfaLyE="
phrase = '{"name":"Bob","email":"user@example.com","address":"Singapore"}'


class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = base64.urlsafe_b64decode(key.encode())

    def encrypt(self, raw):
        raw = pad(raw.encode(), self.bs)
        iv = Random.new().read(self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.urlsafe_b64encode(iv + cipher.encrypted(raw)).decode()

    def decrypt(self, enc):
        enc = base64.urlsafe_b64decode(enc.encode())
        iv = enc[:self.bs]
        text_bytes = enc[self.bs:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(text_bytes), self.bs).decode()


print('secret key: ', secret_key)
print('phrase: ', phrase)

aes = AESCipher(secret_key)
encrypted = aes.encrypt(phrase)

print('encrypted:', encrypted)
print('decrypted:', aes.decrypt(encrypted))

assert aes.decrypt(encrypted) == phrase
