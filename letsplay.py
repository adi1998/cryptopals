import scipy.misc as smp
import numpy as np
a=map(int,(file("../l3ts_pl4y_1.txt").read()).split())
a=np.array(a).reshape((887,900,3))
img=smp.toimage(a)
smp.imsave("temp.png",a)