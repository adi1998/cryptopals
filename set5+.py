from os import urandom
from hashlib import sha1
from DH import DiffieHellman
from set1 import cbcde
import srp

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff 

def c33_DH():
	p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff 
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
	i = 'example@example.com'
	p = urandom(8).encode('hex')

	srv = srp.Server(i,p)
	usr = srp.Client(i,p)

	srv.recv_A(usr.send_A())
	usr.recv_salt_B(*srv.send_salt_B())

	srv.compute_u()
	usr.compute_u()

	print usr.validate(srv)

c36()