a,b=map(int,raw_input().split())
c,d=map(int,raw_input().split())
l=[]
for i in xrange(1100):
	f=0
	for j in  xrange(1100):
		if (b+i*a==d+j*c):
			l.append(b+i*a)
if l:
	print min(l)
else:
	print -1