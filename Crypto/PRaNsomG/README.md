# PRaNsomG

Author : Muhammed Ashique

>Following the mole's dismissal, the nation suffered from an onslaught of relentless phishing campaigns. With little time to spare during this chaotic and tense period, warnings and safeguards for staff members were inadequate. A few individuals fell victim to the phishing attempts, leading to the encryption of sensitive documents by ransomware. You were assigned the mission of reverse engineering the ransomware and ultimately recovering the classified files, restoring order and safeguarding the nation's sensitive information.

## About the Challenge
We have a zip file containing a Python file and a folder that has some encrypted files.
Here is the content of `ransomware.py`
```python
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from random import getrandbits
import os, sys


class Encryptor:

    def __init__(self):
        self.out_dir = 'enc_files'
        self.counter = 0
        self.otp = os.urandom(2)
        self.initialize()

    def initialize(self):
        os.makedirs(f'./{self.out_dir}', exist_ok=True)

        self.secrets = []

        for _ in range(32):
            self.secrets.append(getrandbits(576))

        self.key = l2b(getrandbits(1680))[:16]
        self.iv = l2b(getrandbits(1680))[:16]

        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

    def _xor(self, a, b):
        return b''.join([bytes([a[i] ^ b[i % len(b)]]) for i in range(len(a))])

    def encrypt(self, target):
        for fname in os.listdir(target):
            with open(f'{target}/{fname}') as f:
                contents = f.read().rstrip().encode()

            enc_fname = f"{str(self.counter + 1)}_{fname.split('.')[0]}.enc"

            enc = self.cipher.encrypt(pad(contents, 16))
            enc += self._xor(l2b(self.secrets[self.counter]), self.otp)

            self.write(enc_fname, enc)
            self.counter += 1

    def write(self, filepath, data):
        with open(f'{self.out_dir}/{filepath}', 'wb') as f:
            f.write(data)

def main():
    encryptor = Encryptor()
    encryptor.encrypt(sys.argv[1])

if __name__ == "__main__":
    main()
```

The ransomware first generates 32 random 576-bits numbers and then produces the key and initialization vector for encryptor. On the other hand, it uses a 2-bytes OTP to encrypt the 32 random numbers and appends them to the corresponding encrpyted files.

## How to Solve?

Clearly, our goal is to recover the key and iv from the 32 random numbers. The straightforward approach is to crack the PRNG, which is MT19937 in this case. However, we have only 32×576 < 19937 bits.
Let’s study the PRNG deeper, here is the way that MT19937 updates the internal states:
```python
for i in range(0, 623+1):
    y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] & 0x7fffffff)  
    self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
    if (y % 2) != 0:
        self.MT[i] = self.MT[i] ^ (2567483615)
```
Aand the output is generated as follow:
```
if self.index == 0:
    self.generate_numbers()
y = self.MT[self.index]
y = y ^ (y >> 11)
y = y ^ ((y << 7) & (0x9d2c5680))
y = y ^ ((y << 15) & (0xefc60000))
y = y ^ (y >> 18)
self.index = (self.index + 1) % 624
return y
```

From the output, it’s not hard to convery it back to the internal state and most importantly, any new internal state depends on only 3 previous states. Therefore, we could still figure out the key and iv using less than 19937-bits output.

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
import random
import os

def USR(x, shift):
	res = x
	for i in range(32):
		res = x ^ res >> shift
	return res

def USL(x, shift, mask):
	res = x
	for i in range(32):
		res = x ^ (res << shift & mask)
	return res

def to_MT(v):
	v = USR(v, 18)
	v = USL(v, 15, 0xefc60000)
	v = USL(v, 7, 0x9d2c5680)
	v = USR(v, 11)
	return v

def to_random(y):
    y = y ^ (y >> 11)
    y = y ^ ((y << 7) & (0x9d2c5680))
    y = y ^ ((y << 15) & (0xefc60000))
    y = y ^ (y >> 18)
    return y

def xor(a, b):
	return b''.join([bytes([a[i] ^ b[i % len(b)]]) for i in range(len(a))])

def recover(a, b, c, otp):
	a = bytes_to_long(xor(a, otp))
	b = bytes_to_long(xor(b, otp))
	c = bytes_to_long(xor(c, otp))
	res = []
	MT_i, MT_iadd1, MT_iadd397 = to_MT(a), to_MT(b), to_MT(c)
	y = (MT_i & 0x80000000) + (MT_iadd1 & 0x7fffffff)
	MT_iadd624 = MT_iadd397 ^ (y >> 1)
	if (y % 2) != 0:
		MT_iadd624 = MT_iadd624 ^ 0x9908b0df
	return long_to_bytes(to_random(MT_iadd624))

def pad(s, L):

	return (L - len(s)) * b"\x00" + s

DEBUG = False

if not DEBUG:

	folder = "./enc_files/"
	files = os.listdir(folder)
	sorted_files = []
	for i in range(32):
		for fname in files:
			if fname.startswith(str(i) + "_"):
				sorted_files += [fname]
				files.remove(fname)
				break 

	enc, outputs = [], []
	for fname in sorted_files:
		with open(folder + fname, "rb") as f:
			tmp = f.read()
			enc += [tmp[:-72]]
			_ = tmp[-72:]
		for i in range(17, -1, -1):
			outputs += [_[4 * i: 4 * i + 4]]
else:
	# random.seed(12345678)
	outputs = []
	for _ in range(576):
		outputs += [long_to_bytes(random.getrandbits(32))]
	_key = long_to_bytes(random.getrandbits(1680))[:16]
	_iv = long_to_bytes(random.getrandbits(1680))[:16]

"""
	0, 1, ..., 575 (576)
	576, 577, ..., 627, 628 (1680 / 32 = 52.5)
	629, 630, ..., 680, 681
"""

for n in range(1 if DEBUG else 256**2):
	otp = pad(long_to_bytes(n), 2)

	key = recover(outputs[4], outputs[5], outputs[401], otp)[:2] + \
		pad(recover(outputs[3], outputs[4], outputs[400], otp), 4) + \
		pad(recover(outputs[2], outputs[3], outputs[399], otp), 4) + \
		pad(recover(outputs[1], outputs[2], outputs[398], otp), 4) + \
		pad(recover(outputs[0], outputs[1], outputs[397], otp), 4)[:2]
	
	iv = recover(outputs[57], outputs[58], outputs[454], otp)[:2] + \
		pad(recover(outputs[56], outputs[57], outputs[453], otp), 4) + \
		pad(recover(outputs[55], outputs[56], outputs[452], otp), 4) + \
		pad(recover(outputs[54], outputs[55], outputs[451], otp), 4) + \
		pad(recover(outputs[53], outputs[54], outputs[450], otp), 4)[:2]

	if not DEBUG:
		cipher = AES.new(key, AES.MODE_CBC, iv)
		for i, e in enumerate(enc):
			try:
				pt = cipher.decrypt(enc[i])
				print(pt.decode())
				print(i)
			except:
				pass
	else:
		assert key == _key and iv == _iv
```
### Flag
```
HTB{v1t4l1um_h3r3_w3_c0m3___n0_r4ns0mw4r3_c4n_st0p_us}
```
