def genbyte(l):
	from random import randint
	return ''.join([chr(randint(0,255)) for i in xrange(l)])
def genkey():
	return genbyte(16)
def paddata(data):
	padlen=len(data)%16
	pad=chr(16-padlen)*(16-padlen)
	return data+pad

def xor(a,b):
	return ''.join([chr(ord(a[i])^ord(b[i%len(b)])) for  i in xrange(len(a))])

def cbcen(data,key,iv="\x00"*16):
	from Crypto.Cipher import AES
	a=AES.new(key,AES.MODE_ECB)
	padlen=len(data)%16
	pad=chr(padlen)*padlen
	data=data+pad
	prev=iv
	enc=''
	for i in xrange(0,len(data),16):
		temp=data[i:i+16]
		enc+=a.encrypt(xor(prev,temp))
		prev=a.encrypt(xor(prev,temp))
	return enc

def cbcde(data,key,iv="\x00"*16):
	from Crypto.Cipher import AES
	a=AES.new(key,AES.MODE_ECB)
	prev=iv
	de=''
	for i in xrange(0,len(data),16):
		temp=data[i:i+16]
		de+=xor(prev,a.decrypt(temp))
		prev=temp
	return de
def padval(data):
	for i in xrange(16,-1,-1):
		if data[-i:]==chr(i)*i:
			return True
	return False
key17=genkey()
iv=genkey()
data_list='''
			 MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
			 MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
			 MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
			 MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
			 MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
			 MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
			 MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
			 MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
			 MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
			 MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
		  '''.split()
def aes128():
	from random import randint
	data=paddata(data_list[randint(0,9)].decode('base64'))
	return cbcen(data,key17,iv)
def oracle(cipher):
	msg=cbcde(cipher,key17,iv)
	return padval(msg)
cipher=aes128()
n=len(cipher)/16
prev=iv
for i in xrange(n):
	block=cipher[i*16:(1+i)*16]
	ins=''
	ans=''
	for j in xrange(1,16):
		for k in xrange(256):
			if oracle('a'*(16-j)+chr(k)+ins+block):
				temp=k^(j)
				ans=chr(temp)+ans
				print len(ins),j
				ins=xor(ans,chr((j+1))*(j))
				break
	print xor(ans,prev)
	prev=block
