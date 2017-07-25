#!/usr/bin/env python
from random  import randint
import struct

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4(object):
    def __init__(self, data=""):
        self.remainder = data
        self.count = 0
        self.h = [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
                ]

    def _add_chunk(self, chunk):
        self.count += 1
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4 
            h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def add(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in xrange(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def finish(self):
        l = len(self.remainder) + 64 * self.count
        self.add( "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8) )
        out = struct.pack("<4I", *self.h)
        #for i in self.h:print hex(i),
        #print out.encode('hex')
        #self.__init__()
        return out.encode('hex')

    def change_state(self,new_hash,l):
    	self.h=[struct.unpack('<Q',new_hash[i*8:i*8+8]) for i in xrange(4)]
    	self.remainder=''
    	self.count=l/64
    	#print self.count,l
    	return self
    def reset(self):
    	self.__init__()
if __name__=="__main__":
    test = (
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
            ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")
        )
    md = MD4()
    for t, h in test:
        md.add(t)
        d = md.finish()
        #print d
        if d == h:
            print "pass"
        else:
            print "FAIL: {0}: {1}\n\texpected: {2}".format(t, d.encode("hex"), h)

def forge_padding(message):
	l=len(message)
	return "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8)

def calc_bytes(message):
    return len(message)+len(forge_padding(message))

#assuming we somehow know the keylength

keylen=randint(5,10)
key='a'*keylen
print(keylen)

message="comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
addend=";admin=true"
#print len(message)
mac=MD4().add(key+message)

h1=mac.finish()
#print(h1)

forge=MD4().change_state(h1,calc_bytes('b'*keylen+message))

forge.add(addend)
print(forge.finish())

new_message=message+forge_padding('b'*keylen+message)+addend
check=MD4().add(key+new_message).finish()
print(check)

print (repr(new_message))
