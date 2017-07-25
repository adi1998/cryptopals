from os import *
from set1 import cbcen,cbcde,unpad
from hashlib import sha1

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff 

def proccess_hex(num):
	a=hex(num)[2:].strip('L')
	a='0'*(len(a)%2)+a
	return a.decode('hex')

class DiffieHellman(object):

	def __init__(self,p=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff ,g=2):
		self.p=p
		self.g=g
		self._m=[] # stores all messages received
		self._compute_keys()

	def _compute_keys(self):
		self._a=int(urandom(200).encode('hex'),16) % self.p
		self.A=pow(self.g, self._a, self.p)

	def compute_secret(self,B):
		self._s = pow(B, self._a, self.p)
		self._aes_key = sha1(proccess_hex(self._s)).digest()[:16]

	def send_public(self):
		return self.p, self.g, self.A

	def encrypt(self,msg):
		iv=urandom(16)
		return cbcen(msg,self._aes_key,iv) + iv

	def decrypt(self,cipher):
		iv=cipher[-16:]
		cipher=cipher[:-16]
		self._m.append(cbcde(cipher,self._aes_key,iv))
		#print self._m