def binary_search(a, n):
    beg = 0
    end = len(a) - 1
    while True:
        if end < beg:
            return -1
        mid = (beg + end)/ 2
        if a[mid] < n:
            beg = mid + 1
        elif a[mid] > n:
            end = mid - 1
        else:
            return mid
f=0
n,m=map(int,raw_input().split())
for i in xrange(m):
	a=map(int,raw_input().split())[1:]
	a.sort()
	f=0
	for i in a:
		if binary_search(a,-i)!=-1:
			f=1
			break
	if f==0:
		print "YES"
		break
else:
	print "NO"
