def is_overlapping(x1,x2,y1,y2):
	x1,x2=sorted([x1,x2])
	y1,y2=sorted([y1,y2])
	return max(x1,y1) <= min(x2,y2)
t=input()
for _ in xrange(t):
	x11,y11,x12,y12=map(int,raw_input().split())
	x21,y21,x22,y22=map(int,raw_input().split())
	if x11==x12 and x21==x22:
		if x11==x21:
			if is_overlapping(y11,y12,y21,y22):
				print 'yes'
			else:
				print 'no'
		else:
			print 'no'
	elif y11==y12 and y21==y22:
		if y11==y21:
			if is_overlapping(x11,x12,x21,x22):
				print 'yes'
			else:
				print 'no'
		else:
			print 'no'
	else:
		if (x11,y11)==(x21,y21) or (x11,y11)==(x22,y22) or (x12,y12)==(x21,y21) or (x12,y12)==(x22,y22):
			print 'yes'
		else:
			print 'no'
