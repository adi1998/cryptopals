from gmpy2 import invert as modinv
from os import urandom
from hashlib import sha1

def int_hex(n):
	temp=hex(n)[2:].strip('L')
	return '0'*(len(temp)%2) + temp

def H(m):
	return int(sha1(int_hex(m).decode('hex')).hexdigest(),16)

def rand(n):
	return int(urandom(n).encode('hex'),16)

p = int(''.join("""800000000000000089e1855218a0e7dac38136ffafa72eda7
                   859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
                   2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
                   ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
                   b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
                   1a584471bb1""".split()),16)
 
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
 
g = int(''.join('''5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
                   458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
                   322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
                   0f5b64c36b625a097f1651fe775323556fe00b3608c887892
                   878480e99041be601a62166ca6894bdd41a7054ec89f756ba
                   9fc95302291'''.split()),16)

class DSA(object):

	def __init__(self,x=None):
		if not x:
			self.x = rand(200) % q
		else:
			self.x=x
		self.y = pow(g,self.x,p)

	def sign(self,m,k=None):
		if not k:
			k = rand(200) % q
		r = pow(g,k,p) % q
		s = (modinv(k,q)*(H(m)+self.x*r)) % q
		return r,s

	def verify(self,r,s,m):
		w = modinv(s,q)
		u1 = (H(m)*w) % q
		u2 = (r*w) % q
		v = (pow(g,u1,p)*pow(self.y,u2,p)) % q
		if v==r :
			return True
		else:
			return False