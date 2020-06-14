import socket
import threading
import sys
import pickle
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

class AES_256():
	"""docstring for AES"""
	#aes = AES.new(key, AES.MODE_OFB, iv)
	def __init__(self):
		self.key = b'01234567890123456789012345678901'
		self.iv = b'0123456789012345'#Random.new().read(AES.block_size)
		self.aes = AES.new(self.key, AES.MODE_OFB, self.iv)
		print('iv =', self.iv)
		print('key =', self.key)
	
	def enc(self, msg):
		ciphertext = self.aes.encrypt(pad(msg, 32))
		self.iv64 = b64encode(self.aes.iv).decode('utf-8')
		self.ciphertext64 = b64encode(ciphertext).decode('utf-8')
		return self.ciphertext64


	def dec(self, data):
		plaintext64 = b64decode(data.decode("utf-8"))
		plaintext = unpad(self.aes.decrypt(plaintext64), 32)
		return plaintext

class Cliente(AES_256):
	"""docstring for Cliente"""
	
	def __init__(self, host="localhost", port=4000):
		
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((str(host), int(port)))

		self.aes = AES_256()

		msg_recv = threading.Thread(target=self.msg_recv)

		msg_recv.daemon = True
		msg_recv.start()

		while True:
			msg = input('->')
			if msg != 'salir':
				self.enc_msg = self.aes.enc(str.encode(msg))
				print("CIPHER TEXT SEND:::::", self.enc_msg)
				self.send_msg(self.enc_msg)
			else:
				self.sock.close()
				sys.exit()

	def msg_recv(self):
		while True:
			try:
				data = self.sock.recv(1024)
				if data:
					print("CIPHERTEXT REC::::::", data)
					plaintext = self.aes.dec(data)
					print("PLAINTEXT REC:::::::", plaintext)
			except Exception as e:
				print(e)

	def send_msg(self, msg):
		self.sock.send(str.encode(msg))


c = Cliente()
