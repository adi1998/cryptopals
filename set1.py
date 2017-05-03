d={"E":12.02,
" ": 15.00,
"T": 9.10,
"A": 8.12,
"O": 7.68,
"I": 7.31,
"N": 6.95,
"S": 6.28,
"R": 6.02,
"H": 5.92,
"D": 4.32,
"L": 3.98,
"U": 2.88,
"C": 2.71,
"M": 2.61,
"F": 2.30,
"Y": 2.11,
"W": 2.09,
"G": 2.03,
"P": 1.82,
"B": 1.49,
"V": 1.11,
"K": 0.69,
"X": 0.17,
"Q": 0.11,
"J": 0.10,
"Z": 0.07}

def hamming(a,b):
	return bin(int(a.encode("hex"),16)^int(b.encode("hex"),16))[2:].count("1")
def normham(s,l):
	ham=0.0
	for i in xrange(len(s)/l-1):
		ham+=hamming(s[i*l:(i+1)*l],s[i*l+l:i*l+2*l])
	ham=ham/(len(s)*1.0/l)
	ham=ham/l
	return ham
def score(s):
	return sum(map(lambda y:d.get(y,0),s.upper()))

def c1(s):
	return s.decode("hex").encode("base64")
def c2(a,b):
	return hex(int(a,16)^int(b,16))[2:].replace("L","")
def c3(x):
	s=x.decode("hex")
	m=0
	ans=''
	key=0
	for i in xrange(256):
		temp=''.join([chr(ord(j)^i) for j in s])
		score=sum(map(lambda y:d.get(y,0),temp.upper()))
		if score>m:
			m=score
			ans=temp
			key=i
	return ans,m,key
def c4():
	return max([c3(i) for i in file("4.txt").read().split()],key= lambda y:y[1])
def c5(a,b):
	return ''.join([chr(ord(a[i])^ord(b[i%len(b)])) for i in xrange(len(a))]).encode("hex")
def c6():
	msg=''.join(file("6.txt").read().split()).decode("base64")
	#msg=file("enc.enc").read()
	msg="RIVXR ITWZV OHVFM HVBMV HFVHC GLHEG RZHVR VS"
	keylen=1;
	for i in xrange(2,30):
		keylen=min(keylen,i, key=lambda y:normham(msg,y))
		print normham(msg,i),i
	print "Most probable keylength:",keylen
	#print msg
	blocks=[msg[i::keylen] for i in  xrange(keylen)]
	fkey=[]
	for b in blocks:
		fkey.append(chr(c3(b.encode("hex"))[2]))
	print "Most probable key      :",''.join(fkey)
	print "Message:"
	print c5(msg,fkey).decode("hex")
def c7():
	from Crypto.Cipher import AES
	msg=''.join(file("7.txt").read().split()).decode("base64")
	aes=AES.new("YELLOW SUBMARINE",AES.MODE_ECB)
	print aes.decrypt(msg)
def c8():
	from Crypto.Cipher import AES
	f=file("8.txt").read().split()
	for i in f:
		for j in xrange(0,len(i)-32,32):
			if i.count(i[j:j+32])>1:
				print i
				return 1
	return 0
def c9(s,l):
	return (s+chr((l-len(s)))*(l-len(s)))
def c10():
	from Crypto.Cipher import AES
	f=''.join(file("10.txt").read().split()).decode("base64")
	#print f
	prev="\x00"*16
	ans=''
	for i in xrange(0,(len(f)/16)*16,16):
		temp=f[i:i+16]
		ans+=(c5(prev,AES.new("YELLOW SUBMARINE",AES.MODE_ECB).decrypt(c9(temp,16	)))).decode("hex")
		prev=temp
	#ans+=(c5(prev,c9(f[(len(f)/16)*16:],16))).decode("hex")
	return ans

# Challenge 11

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
	enc=''
	for i in xrange(0,len(data),16):
		temp=data[i:i+16]
		enc+=xor(prev,a.decrypt(temp))
		prev=temp
	return enc

def genbyte(l):
	from random import randint
	return ''.join([chr(randint(0,255)) for i in xrange(l)])
def genkey():
	return genbyte(16)
def enc_oracle(data):
	from random import randint
	from Crypto.Cipher import AES
	key=genkey()
	a=AES.new(key,AES.MODE_ECB)
	temp=genbyte(randint(5,10)) + data + genbyte(randint(5,10))
	temp=paddata(temp)
	if randint(0,1):
		return a.encrypt(temp)
	else:
		iv=genkey()
		return cbcen(temp,key,iv)
def ecb_cbc(data):
	for i in data:
		for j in xrange(0,len(i)-16,16):
			if i.count(i[j:j+16])>1:
				return "ECB"
	return "CBC"
from Crypto.Cipher import AES
def c12():
	key12=genkey()
	def aes128(data):
		from Crypto.Cipher import AES
		unknown="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
		unknown=unknown.decode("base64")
		a=AES.new(key12,AES.MODE_ECB)
		return a.encrypt(paddata(data+unknown))
	message="A"*15
	n=len(aes128(''))
	try:
		for b in xrange(n/16):
			for i in xrange(15,-1,-1):
				d={}
				for j in xrange(256):
					d[aes128(message[-15:]+chr(j))[:16]]=message[-15:]+chr(j)
				payload="A"*i
				temp=aes128(payload)
				message+=d[temp[(b)*16:(b)*16+16]][-1]
	except KeyError:
		return message[15:-1]
	else:
		pass

def unpad(data):
	c=ord(data[-1])
	if data[-c:]==c*data[-1]:
		return data[:-c]
	elif ord(data[-1]) in range(16):
		raise Exception
	else:
		return data

def c13():
	def parser(data):
		data=map(lambda x:x.split("="),data.split("&"))
		return {i[0]:i[1] for i in data}

	def profile_for(email):
		email=email.replace("&","").replace("=","")
		ret="email="+email+"&"+"uid=10&role=user"
		return ret
	key13=genkey()
	def encryptcookie(cook):
		from Crypto.Cipher import AES
		a=AES.new(key13,AES.MODE_ECB)
		return a.encrypt(paddata(cook))
	def decryptcookie(cook):
		from Crypto.Cipher import AES
		a=AES.new(key13,AES.MODE_ECB)
		return parser(unpad(a.decrypt(cook)))
	print parser("foo=bar&baz=qux&zap=zazzle")
	emp="a"*10+paddata("admin")

	a=raw_input("Enter email:")
	b=encryptcookie(profile_for(emp))
	admincook=b[16:32]
	e2="aaaaaa@aa.com&"
	c=encryptcookie(profile_for(e2))
	final=c[:32]+admincook
	finald=decryptcookie(final)
	print finald
	print repr(b)
def c14():
	from random import randint
	key14=genkey()
	prefix=genbyte(randint(5,10))
	def aes128(data):
		from Crypto.Cipher import AES
		unknown="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
		unknown=unknown.decode("base64")
		a=AES.new(key14,AES.MODE_ECB)
		return a.encrypt(paddata(prefix+data+unknown))
	offset=0
	while True:
		temp=aes128("a"*offset+"a"*32)
		if  temp[16:32]==temp[32:48]:
			break
		offset+=1


	message="A"*15
	n=len(aes128(''))-16
	try:
		for b in xrange(n/16):
			for i in xrange(15,-1,-1):
				d={}
				for j in xrange(256):
					d[aes128("a"*offset+message[-15:]+chr(j))[16:][:16]]=(message[-15:]+chr(j))
				payload='a'*offset+"A"*i
				temp=aes128(payload)[16:]
				message+=d[temp[(b)*16:(b)*16+16]][-1]
	except KeyError:
		return message[15:-1]
	else:
		pass

def c15(data):
	for i in xrange(15,-1,-1):
		if data[-i:]==chr(i)*i:
			return True
	return False

def c16():
	key16=genkey()
	def aes128(data):
		from Crypto.Cipher import AES
		a1="comntd1=cdwxxxg%20MCs;userdata="
		a2=";comment2=%20like%20a%20pound%20of%20bacon"
		return cbcen(paddata(a1+data.replace("=","").replace(";","")+a2),key16)
	def check(data):
		rev=unpad(cbcde(data,key16))
		if ["admin","true"] in map(lambda x: x.split("="),rev.split(";")):
			return True
		return False
	offset1=0
	offset2=0
	temp=aes128('')	
	temp2=aes128('a')

	for i in xrange(len(temp)/16):
		if temp[i*16:i*16+16]!=temp2[i*16:i*16+16]:
			offset1=i
			break
	for i in xrange(16):
		if aes128('a'*i)[16*offset1:16*offset1+16]==aes128("a"*(i+1))[16*offset1:16*offset1+16]:
			offset2=i
			break
	print offset2
	if offset2!=0:
		comm=(offset1+1)*16
	else:
		comm=(offset1)*16
	print comm
	rec=aes128('b'*offset2+"a"*16+"b"*16)
	mod=xor(xor('b'*16,";admin=true;aaaa"),rec[comm:comm+16])
	payload=rec[:comm]+mod+rec[comm+16:]
	print check(payload)

def c17():
	key17=genkey()
	data_list='''MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'''.split()
	def aes128():
		from random import randint
		data=paddata(data_list[randint(0,9)])
		return cbcen(data,key17)
	def oracle(cipher):
		msg=cbcde(cipher,key17)
		return c15(msg)
	
