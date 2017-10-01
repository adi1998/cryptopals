from os import urandom
from hashlib import sha1
from DH import DiffieHellman
from set1 import cbcde
from gmpy2 import invert
import srp,srp_simple
import sys

sys.setrecursionlimit(15000)

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff 
N = p

def int_hex(n):
	temp=hex(n)[2:].strip('L')
	return '0'*(len(temp)%2) + temp

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def cbrt(n,beg,end):
	mid = (beg+end)/2
	if mid**3<=n and (mid+1)**3>=n:
		return mid+1
	elif mid**3<n:
		return cbrt(n,mid+1,end)
	else:
		return cbrt(n,beg,mid-1)

def c33():
	g = 2
	a = int(urandom(200).encode('hex'),16) % p #secret to A
	A = pow(g,a,p)
	b = int(urandom(200).encode('hex'),16) % p #secret to B
	B = pow(g,b,p)
	s1 = pow(B,a,p)
	s2 = pow(A,b,p)
	assert s1==s2
	s=s1 # mutual secret
	return p,g,A,a,B,b,s1

def c34():
	Alice = DiffieHellman()

	Mp, Mg, MA = Alice.send_public() # A->M

	Bob = DiffieHellman(Mp,Mg)
	Bob.compute_secret(Mp) # M->B

	Mp, Mg, MB = Bob.send_public() # B->M

	Alice.compute_secret(Mp) # M->A

	msg1 = urandom(8).encode('hex')
	msg2 = urandom(8).encode('hex')

	en1 = Alice.encrypt('message1')
	Men1 = cbcde(en1[:-16],sha1('\x00').digest()[:16],en1[-16:])
	print Men1
	Bob.decrypt(en1)

	en2 = Bob.encrypt('message2')
	Men2 = cbcde(en2[:-16],sha1('\x00').digest()[:16],en2[-16:])
	print Men2
	Bob.decrypt(en2)

def c35():
	def solve(Mg,Mkey):
		Alice = DiffieHellman(g=Mg)
		p,g,A=Alice.send_public()
		
		Bob = DiffieHellman(g=Mg)

		p,g,B=Bob.send_public()
		
		Alice.compute_secret(B)
		Bob.compute_secret(A)
		
		msgA = 'message1'
		msgB = 'message2'

		en1 = Alice.encrypt(msgA)
		en2 = Bob.encrypt(msgB)

		M1 = cbcde(en1[:-16],sha1(Mkey).digest()[:16],en1[-16:])
		M2 = cbcde(en2[:-16],sha1(Mkey).digest()[:16],en2[-16:])

		print repr((M1))
		print repr((M2))

	solve(1,'\x01')
	solve(p,'\x00')
	solve(p-1,proccess_hex(p-1))
	solve(p-1,'\x01')

def c36():
	I = 'example@example.com'
	P = urandom(8).encode('hex')

	srv = srp.Server(I,P)
	usr = srp.Client(I,P)

	srv.recv_A(usr.send_A())
	usr.recv_salt_B(*srv.send_salt_B())

	srv.compute_u()
	usr.compute_u()

	print usr.validate(srv)

def c37():
	def solve(n):
		I = 'example@example.com'
		P = urandom(8).encode('hex')

		srv = srp.Server(I,P)
		usr = srp.Client(I,P)

		srv.recv_A(N*i)
		usr.recv_salt_B(*srv.send_salt_B())

		srv.compute_u()
		usr.compute_u()

		print usr.validate(srv,srp.hmac_sha256(srp.sha256(srp.int_to_str(0)).hexdigest(),usr.salt))

	for i in range(3):
		solve(i)

def c38():
	I = 'example@example.com'
	P = urandom(8).encode('hex')

	srv = srp_simple.Server(P)
	usr = srp_simple.Client(P)

	srv.recv_A(usr.send_A())
	usr.recv_data(*srv.send_data())

	srv.gen_K()
	usr.gen_K()

	print usr.validate(srv)

#skipping bruteforce SRP for now

def c39():
	import RSA
	a = RSA.RSAKey(4096)
	c = a.encrypt('Secret Message')
	print a.decrypt(c)

def c40():
	import RSA
	def ms(n,i):
		ans=1
		for j in xrange(len(n)):
			if j!=i:
				ans*=n[j]
		return ans

	def crt(c,n):
		assert len(c)==len(n)
		result = 0
		N=1
		for i in xrange(len(c)):
			result += c[i]*ms(n,i)*invert(ms(n,i),n[i])
			N*=n[i]
		return result % N

	def cbrt(n,beg,end):
		mid = (beg+end)/2

		if mid**3 == n:
			return mid
		elif mid**3>n:
			return cbrt(n,beg,mid-1)
		else:
			return cbrt(n,mid+1,end)

	a1 = RSA.RSAKey(4096)
	a2 = RSA.RSAKey(4096)
	a3 = RSA.RSAKey(4096)

	c1 = a1.encrypt('Secret Message')
	c2 = a2.encrypt('Secret Message')
	c3 = a3.encrypt('Secret Message')

	n1 = a1.send_public()[0]
	n2 = a2.send_public()[0]
	n3 = a3.send_public()[0]

	result = (crt((c1,c2,c3),(n1,n2,n3)))
	result = cbrt(result,2,result)
	print srp.int_to_str(result)

def c41():
	import RSA

	a = RSA.RSAKey(4096)
	c = a.encrypt('Secret Message')
	n,e = a.send_public()

	s = int(urandom(4096/8).encode('hex'),16) % n
	s=3
	cn = (pow(s,e,n)*c) % n

	pn = int(a.decrypt(cn).encode('hex'),16)

	temp = modinv(s,n)

	p = (temp*pn) % n

	print srp.int_to_str(p)


def c42():
	import RSA
	import re

	asn1 = "003021300906052b0e03021a05000414"
	
	def pad(data):
		ans = asn1+data
		n=len(ans)
		padding = '0001'+'f'*(1024/4-n-4)
		return padding + ans

	def verify(n,e,data,sign):
		hash = sha1(data).hexdigest()
		ver = hex(pow(sign,e,n))[2:].rstrip('L')
		if re.match("1(ff)+"+asn1+hash,ver):
			return True
		else:
			return False

	def signer(n,d,data):
		hash = sha1(data).hexdigest()
		pk = int(pad(hash),16)
		ver = pow(pk,d,n)
		return ver

	def forge_sign(data):
		pk = '0001ffffffffff'+asn1+sha1(data).hexdigest()
		n=len(pk)
		pk += (1024/4-n)*'0'
		pk = int(pk,16)
		return cbrt(pk,2,pk)

	key = RSA.RSAKey()
	n,d,e=key.n,key.d,key.e
	message = "hi mom"
	a=signer(n,d,message)
	print verify(n,e,message,a)
	print verify(n,e,message,forge_sign(message))

def c43():
	from DSA import q,DSA

	def computex(s,k,h_m,r,q):
		return ((s*k - h_m)*invert(r,q)) % q

	check_hex = '0954edd5e0afe5542a4adf012611a91912a3ec16'

	d = DSA()
	y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
	h_m = 0xd2d0714f014a9784047eaeccf956520045c45265
	r = 548099063082341131477253921760299949438196259240
	s = 857042759984254168557880549501802188789837994940
	 
	msg = 'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'

	m = int(msg.encode('hex'),16)



	for k in xrange(1,2**16):
		x = computex(s,k,h_m,r,q)
		d = DSA(x)
		if d.sign(m,k)==(r,s):
			print x
			assert sha1(hex(x)[2:].strip('L')).hexdigest() == check_hex
			break

def c44():
	from DSA import q,DSA

	def computex(s,k,h_m,r,q):
		return ((s*k - h_m)*invert(r,q)) % q

	def getk(s1,s2,m1,m2):
		return (m1-m2)*int(invert(s1-s2,q)) % q

	f = file('44.txt').readlines() 
	n = len(f)
	l = []
	for i in xrange(n/4):
		msg = f[i*4][5:-1]
		s = int(f[i*4+1][3:])
		r = int(f[i*4+2][3:])
		m = int(f[i*4+3][3:],16)
		l.append((msg,s,r,m))
	
	check = []

	check_hex = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'

	for i in  xrange(n/4-1):
		for j in xrange(i+1):
			
			try:
				k = getk(l[i][1],l[j][1],l[i][-1],l[j][-1])
				x = computex(l[i][1],k,l[i][-1],l[i][2],q)
				d = DSA(x)
				if d.sign(int(l[i][0].encode('hex'),16),k)==(l[i][2],l[i][1]):
					print x
					print hex(d.y)
					print sha1(hex(x)[2:].strip('L')).hexdigest()
					assert sha1(hex(x)[2:].strip('L')).hexdigest() == check_hex
					break
			except ZeroDivisionError:
				pass


def c45():
	from DSA import rand,H

	def sign(msg,p,q,g,x):
		k = rand(200) % q
		r = pow(g,k,p) % q
		s = (modinv(k,q)*(H(int(msg.encode('hex'),16)) + x*r)) % q
		return r,s

	def verify(r,s,m,y,p,q):
		w = modinv(s,q)
		u1 = (H(int(m.encode('hex'),16))*w) % q
		u2 = (r*w) % q
		v = (pow(g,u1,p)*pow(y,u2,p)) % q
		if v==r :
			return True
		else:
			return False

	p = int(''.join("""800000000000000089e1855218a0e7dac38136ffafa72eda7
                   859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
                   2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
                   ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
                   b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
                   1a584471bb1""".split()),16)
 
	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

	g = 0 

	#param
	x = rand(200) % q
	y = pow(g,x,p)

	s1 = sign('message',p,q,g,x)

	print verify(s1[0],s1[1],'message',y,p,q)

	#forge sign
	msg  = 'Super Important Message'
	sf = (0, H(int(msg.encode('hex'),16)*7) % q)

	print verify(0,sf[1],msg,0,p,q)
	
	g=p+1
	z=2353
	y=pow(g,x,p)
	r=pow(y,z,p)%q
	s=(modinv(z,q)*r)%q
	print verify(r,s,'skjhgirgrgbsihgiudgiugiudh',y,p,q)

def  c46():
	import time
	def int_hex(n):
		temp=hex(n)[2:].strip('L')
		return '0'*(len(temp)%2)+temp
	import RSA
	msg = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='.decode('base64')
	key = RSA.RSAKey(1024)
	n,e=key.send_public()
	c = key.encrypt(msg)
	temp = c
	beg = 0
	end = n
	while beg<end:

		mid = (beg+end)/2
		temp = (pow(2,e,n)*temp)%n
		if not key.parity_oracle(temp):
			end=mid
		else:
			beg=mid
		T = (int_hex(end).decode('hex').strip()).strip()
		
		print (T)
			#print end-beg
		time.sleep(0.01)
		
def c47():

	def PKCS_pad(m,k):
		d=len(m)
		if d>k-11:
			raise ValueError
		ps = ''.join([chr(int(urandom(1).encode('hex'),16) % 255 + 1) for _ in xrange(k-3-d)])
		return "\x00\x02" + ps + '\x00' + m

	def blind(key,c,s):
		return key.encrypt(int_hex(s).decode('hex'))*c % key.n

	def compute_M(M,s,B,n):
		tM=[]
		for a,b in M:
			rL=(a*s[-1]-3*B+1+n-1)/n
			rH=(b*s[-1]-2*B)/n+1
			r=rL
			while r <  rH:

				tM.append((max(a,(2*B+r*n+s[-1]-1)/s[-1]),min(b,(3*b-1+n*r)/s[-1])))
				if tM[-1][0]>tM[-1][1]:
					tM.pop(-1)
				r+=1
		tM.sort()
		return tM
		sM=[tM[0]]
		for i in tM[1:]:
			if i[0]<=sM[-1][1]:
				sM[-1]=(min(sM[-1][0],i[0]),max(i[1],sM[-1][1]))
			else:
				sM.append(i)
		return sM

	from RSA import RSAKey

	bits = 768
	key = RSAKey(bits,2**16+1)
	n=key.n
	B = 2**(8*(bits/8-2))
	msg = PKCS_pad("This is a message for demonstrating the Bleichenbacher's PKCS padding oracle attack",bits/8)
	c=key.encrypt(msg)
	
	s=[1]
	M=[(2*B,3*B-1)]
	C=[c]
	i=1
	while True:
		if i==1:
			s.append(n/(3*B))
			while True:
				temp = blind(key,c,s[1])
				if key.PKCS_oracle(temp):
					break
				s[1]+=1
				#print s[1]
		elif i>1 and len(M)>=2 :
			s.append(s[-1]+1)
			while True:
				temp = blind(key,c,s[-1])
				if key.PKCS_oracle(temp):
					break
				s[-1]+=1
		else:
			a,b=M[0]
			r = 2*(b*s[-1]-2*B+n-1)/n
			while True:
				f=0
				sL=(2*B+r*n+b-1)/b
				sH=(3*B+r*n+a-1)/a
				j=sL
				while j<sH:
					j+=1
					temp = blind(key,c,j)
					if key.PKCS_oracle(temp):
						s.append(j)
						f=1
						break
				if f==1:
					break
				r+=1
		M=compute_M(M,s,B,n)
		print int_hex(M[0][1]).decode('hex')
		if len(M)==1 and M[0][0]==M[0][1]:
			ans = M[0][0]
			break
		i+=1

c47()
