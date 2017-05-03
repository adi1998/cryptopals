
for q in xrange(1,4):
	for w in xrange(1,4):
		string = "7168xy7666781y768x67yx67yx7y36x354xy3x7xy17yx917y8x97yx1x3y11y61y462y498y9727yx87yx9187yx7y897y7y8x78yx78yx78yx78y87yx78yxy87x178yx178y176565165168xy178yx178x9y17y189y7x91xyy8x971x9y79x7yx97yx979798719797979xy79yx7x9y791yx71yx97y7y1xyx9yx7yx97yx9yx79yx7y9x7yx197yx9yx79x"
		a=list(string)

		ans=0
		i=0
		try:
			while True:
				
				if a[i] in "1234567809":
					ans+=int(a[i])
					i+=1
				elif a[i]=="x":
					del a[i]
					i-=1
				elif a[i]=="y":
					del a[i]
					i+=3

				
		except:
			print ans