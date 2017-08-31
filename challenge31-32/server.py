from flask import Flask,request
from time import sleep
from SHA1 import *
app = Flask(__name__)

key='TEST_KEY'

def xor(a,b):
	return ''.join([chr(ord(i)^ord(j)) for i,j in zip(a,b)])

def hash(data):
	return Sha1Hash().update(data).digest()

def compute_hmac(key,message):
	if len(key)>64:
		key=hash(key)
	if len(key)<64:
		key=key+'\x00'*(64-len(key))

	opad=xor('\x5c'*64,key)
	ipad=xor('\x36'*64,key)
	return hash(opad+hash(ipad+message)).encode('hex')

def insecure_compare(a,b):
	for i,j in zip(a,b):
		if i!=j:
			return False
		#sleep(0.005)
	return True

@app.route('/test')
def test():
	if not (request.args.get('file') or request.args.get('signature')):
		return "Send File and Signature"
	else:
		file=str(request.args.get('file'))
		signature=str(request.args.get('signature'))
		#print signature,len(signature)
		if len(signature)!=40:
			return "Enter valid signature"
		hmac = compute_hmac(key,file)
		print hmac
		result = insecure_compare(hmac,signature)
		if result :
			return 'OKAY',200
		else:
			return 'BAD',500