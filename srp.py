from os import urandom
from hashlib import sha256

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff 
g = 2
k = 3

def xor(a,b):
	return ''.join([chr(ord(i)^ord(j)) for i,j in zip(a,b)])

def hash(d):
	return sha256(d).hexdigest()

def hmac_sha256(key,message):
	if len(key)>64:
		key=hash(key)
	if len(key)<64:
		key=key+'\x00'*(64-len(key))

	opad=xor('\x5c'*64,key)
	ipad=xor('\x36'*64,key)
	return hash(opad+hash(ipad+message)).encode('hex')

def int_to_str(n):
	h=hex(n)[2:].strip('L')
	return h.decode('hex')

class Server(object):

	def __init__(self,I,P):
		self.I=I
		self.P=P
		self.salt = urandom(8)
		xH = sha256(self.salt+self.P).hexdigest()
		x = int(xH,16)
		self.v=pow(g,x,N)
		self.b = int(urandom(256).encode('hex'),16) % N
		self.B = (k*self.v + pow(g,self.b,N)) % N
		
	def recv_A(self,A):
		self.A=A

	def send_salt_B(self):
		return self.salt,self.B

	def compute_u(self):
		uH = sha256(int_to_str(self.A)+int_to_str(self.B)).hexdigest()
		self.u = int(uH,16)
		self.gen_K()

	def gen_K(self):
		S=(pow(self.A,self.b,N) * pow(self.v, self.u*self.b, N)) % N
		self.K = sha256(int_to_str(S)).hexdigest()

	def validate(self,hmac):
		if hmac == hmac_sha256(self.K, self.salt):
			return "OK"
		else:
			return "NOT-OK"


class Client(object):

	def __init__(self,I,P):
		self.I=I
		self.P=P
		self.a=int(urandom(256).encode('hex'),16) % N
		self.A=pow(g,self.a,N)

	def send_A(self):
		return self.A

	def recv_salt_B(self,salt,B):
		self.salt=salt
		self.B=B

	def compute_u(self):
		uH = sha256(int_to_str(self.A)+int_to_str(self.B)).hexdigest()
		self.u = int(uH,16)
		self.gen_K()

	def gen_K(self):
		xH = sha256(self.salt+self.P).hexdigest()
		x = int(xH,16)
		S = pow(self.B - k*pow(g,x,N), self.a + self.u*x, N)
		self.K = sha256(int_to_str(S)).hexdigest()

	def validate(self,srv):
		hmac = hmac_sha256(self.K, self.salt)
		return srv.validate(hmac)

