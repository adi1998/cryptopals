from Crypto.Util import number
import gmpy2

def int_hex(n):
	temp=hex(n)[2:].strip('L')
	return '0'*(len(temp)%2) + temp

class RSAKey(object):

	def __init__(self,bits=1024,e=3):
		while True:
			try:
				p=number.getPrime(bits/2)
				q=p
				while p==q:
					q=number.getPrime(bits/2)
				self.n=p*q
				self.e=e
				self.bits=bits
				et=(p-1)*(q-1) 
				self.d=int(gmpy2.invert(self.e,et))
				break
			except:
				pass

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

	def PKCS_oracle(self,c):
		temp = self.decrypt(c)
		if temp[0]=='\x02' and len(temp)==self.bits/8-1:
			return True
		else:
			return False