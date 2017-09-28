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