from timeit import default_timer as timer
import requests as rq

def pad_sign(sign):
	try:
		return sign+'a'*(40-len(sign))
	except:
		return sign

url = "http://localhost:5000/test"

signature = ''
for i in xrange(40):
	a=[]
	for nib in '0123456789abcdef':
		temp=pad_sign(signature+nib)
		b=0
		for i in xrange(6000): # maybe overkill
			start=timer()
			rq.get(url,params={'file':'classified','signature':temp})
			t=timer()-start
			b+=t
		a.append((b,nib))
	signature+=max(a)[1]
	print a
	print signature

print rq.get(url,params={'file':'foo','signature':signature}).text