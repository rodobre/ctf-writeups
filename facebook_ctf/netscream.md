#### Facebook CTF - netscream (919 points)

###### Prelude

The task provides three files, _bin_, _enc_ and _d_. The challenge mentions a mysterious constant involved in this encryption scheme.

###### Summary

The challenge involves decrypting the _enc_ file by successfully predicting the output of the **D**ual **E**lliptic **C**urve **D**eterministic **R**andom Number **G**enerator (or short, Dual EC DRBG).

###### Details

The cryptographic algorithm involved in generating a sequence of random bits from a predefined state (with the help of a random seed), dubbed Dual EC DRBG, has been a heated topic ever since being proposed for NIST standardization. It is believed that the algorithm has a backdoor, in the sense that the fixed point (in our case on the **prime256v1** or **secp256r1** elliptic curve) used for random number generation is the result of multiplying the curve generator with an unknown, secret constant. The standardized algorithm comes with predefined constants for which no explanations were given. This goes against the 'nothing up my sleeve' principle of choosing constants in the cryptographic community.

The task at hand contains a different fixed point. It also provides the secret constant which can be used for compromising the random sequence from a given timestamp, onward.

The algorithm can be understood using this helpful diagram:

![Dual EC DRBG](https://matthewdgreen.files.wordpress.com/2013/09/b9dec-dual_ec_diagram.png)

###### Solution

The steps which need to be taken towards solving the problem are:

* Reversing engineering the binary to understand the behaviour
* Understanding the format of the _enc_ file and extracting data
* Brute-forcing the point for which the next prediction is accurate
* Predicting the key and the next two bytes in order to decrypt

After inspecting the binary, the most important sequences of code involved in the random number generation and encryption are:

```c
ec_point = EC_POINT_new(ec_group);
BN_bin2bn(&bn_initial_x, 0x20, ec_x);// big endian byte sequence of 32 -> ec_x
BN_bin2bn(&bn_initial_y, 0x20, ec_y);         // ec_y
EC_POINT_set_affine_coordinates_GFp(ec_group, ec_other_point, ec_x, ec_y, bignum_ctx);// set other_point = (bignum_in_ec_ctx, ec_x) 
fread(&ptr, 1uLL, 0x20uLL, stream);
return BN_bin2bn(&ptr, 0x20, random_seed);
```

The code above reads 32 (0x20) bytes from _/dev/urandom_ and stores them in ``random_seed``. It also initializes the point used for random number generation with two predefined coordinates.

The actual cryptographic mechanism occurs in the following sequence, ``ec_x`` will be initialized with the random seed for the first call:

```c
EC_POINT_mul(ec_group, ec_point, ec_x, 0LL, 0LL, bignum_ctx);
EC_POINT_get_affine_coordinates_GFp(ec_group, ec_point, ec_x, 0LL, bignum_ctx);

EC_POINT_mul(ec_group, ec_point, 0LL, ec_Q, ec_x, bignum_ctx);
EC_POINT_get_affine_coordinates_GFp(ec_group, ec_point, ec_Q_x, 0LL, bignum_ctx);
```

Here, we have the standard implementation of the algorithm taking place. The backdoor consists of the fact that, by knowing the 'mysterious' constant, we can predict further supposedly-random states, due to the relationship between the generator and Q.

``Q = d * G``

Moreover, thanks to the associative property of scalar multiplication in elliptic curve mathematics, we can make use of the following equality:

``Q * i1 * d = P * i1``, where P represents the point of the previous state, Q is never changed.

The algorithm keeps only the 30 bytes generated, to pad up to 32 bytes, a second prediction is made out of which only 2 bytes are kept. The _enc_ file contains the encrypted flag along with the IV, the algorithm used is AES256 in IGE block-chaining mode. In our case, the IV is composed of the first 30 bytes of the initial prediction and the last 2 bytes of the following generation. Knowing this, we can predict the key, annihilating the security of the algorithm.

The code for finding the first 30 bytes of the password is an adaptation of isaacngym's code, which can be found at [here](https://github.com/isaacngym/Dual-EC-DRBG-exploit-PoC/blob/master/Dual_EC_RBG_commentary.ipynb).

```py
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa import util
from pprint import pprint

G = P256.G
Q = e*G
d = 0x6FC45453894DE99C661581B0A12087B862667B785AABA7116DCDCB3CB3A79AFE

def retrieve_key_from_state(output, second_output, curve):
    # make a new generator and instantiate it with one possible state out of the 65535
    for lsb in range(2**16):
        # rudimentary progress bar
        if (lsb % 2048 == 0):
            print("{}% done checking\r".format(100*lsb/(2**16)))
        # bit-shift and then concat to guess most significant bits that were discarded
        overall_output = ((lsb << 240) | output)

        # zeroth check: is the value greater than p? 
        if overall_output > curve.p:
            print("""Something went wrong. debugging info:
                  Output = {}, 
                  lsb = {}, 
                  rQ = {}""".format(output, lsb, overall_output))
            break

        # calculate a value of y
        for sol_to_y in util.mod_sqrt(overall_output**3 - 3*overall_output + curve.b, curve.p):
            # there are either 2 or 0 real answers to the square root. We reject those greater than p.
            if sol_to_y < curve.p:
                possible_y = sol_to_y
            else:
                possible_y = None
            # first check: if there were 0 solutions we can skip this iteration
        if possible_y == None or type(possible_y) == None:
            continue

        # second check: is point on curve? if not then skip this iteration
        try:
            possible_point = Point(overall_output, possible_y, curve=curve)
        except:
            continue

        # if checks were passed, exploit the relation between state to calculate the internal state
        i2x = (d * possible_point).x
        # check if the state is correct by generating another output
        P = Q * i2x
        tmp_x = hex(P.x)[2:-1]

        if(tmp_x[4:8] == second_output):
            print(possible_point)
            print(tmp_x)
            P = G * i2x
            P = Q * P.x
            print(hex(P.x)[2:-1][4:])
    return 1

retrieve_key_from_state(0xe5cca6d1c93c1160d732fbfb339804e9d9104968da5e087b34ac6061f56a, '9704', P256)
```

The code above would retrieve the first 30 bytes of the AES256 IGE key in a matter of seconds. I decided to brute-force the last 2 bytes so as to avoid any errors:

```py
import binascii
import tgcrypto

key = '38475fb0a7ac9bb193d112e63b2f0b90ebd4509f366671a64bd13bb494a0'
iv = binascii.unhexlify('e5cca6d1c93c1160d732fbfb339804e9d9104968da5e087b34ac6061f56a9704')
ctxt = binascii.unhexlify('539f026ed4b9027c82ecdb764e6f2ef85a4a43dcd1d4bca1e8fc438e8edb094e')

def padhexa(s):
    return '0x' + s[2:].zfill(2)

for i in range(0, 256):
	for j in range(0, 256):
		cp_key = key
		cp_key += padhexa(hex(i & 0xFF))[2:]
		cp_key += padhexa(hex(j & 0xFF))[2:]
		decr = tgcrypto.ige256_decrypt(ctxt, binascii.unhexlify(cp_key), iv)
		
		try:
			decr_str = decr.decode('utf-8').strip()
			if(decr_str[:3] == 'fb{'):
				print(decr_str)
				print("full key is: " + cp_key)
		except:
			continue
```

The code retrieves the AES key used to encrypt the flag. It also decrypts the flag using the python library ``tgcrypto`` which implements the IGE block-chaining mode.

###### Takeaways

* The standardized algorithm was not proven to be backdoored. It is also impossible to prove, since the backdoor constant is probably a very large number.
* The backdoor exists only if the implementation generates Q in the aforementioned way.
* However, the algorithm is deeply flawed (as acknowledged by cryptographers around the world) due to the improper security associated with the small number of bits used, and the lack of efficiency (compared to other cryptographic pseudo-random number generators).
