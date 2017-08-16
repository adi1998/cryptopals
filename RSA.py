from Crypto.PublicKey import RSA
import gmpy2

def int_hex(n):
	temp=hex(n)[2:].strip('L')
	return '0'*(len(temp)%2) + temp

class RSAKey(object):

	def __init__(self,bits=1024,e=3):
		temp=RSA.generate(bits,e=e)
		p=temp.p
		q=temp.q
		self.n=p*q
		self.e=e
		et=(p-1)*(q-1) 
		self.d=int(gmpy2.invert(self.e,et))

	def encrypt(self,m):
		m=int(m.encode('hex'),16)
		return pow(m,self.e,self.n)

	def decrypt(self,c):
		m = pow(c,self.d,self.n)
		return int_hex(m).decode('hex')

	def send_public(self):
		return self.n,self.e

	def send_private(self):
		return self.n,self.d

	def parity_oracle(self,c):
		return pow(c,self.d,self.n)%2

