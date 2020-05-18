### DEFCON CTF 2020 Qualifications - notbefoooled

### Disclaimer

I do cryptography as a pass-time activity. The information provided here is likely to have errors or be incomplete.

### Description

What's the trick to not be foooled?

Files provided:

![Challenge file](/service.sage)

### Walkthrough

Two great resources which have helped me significantly in solving this challenge can be found at [here<sup>1</sup>](https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session1-miele-paper.pdf) and [here<sup>2</sup>](http://www.monnerat.info/publications/anomalous.pdf).

The challenge requires the user to provide the construction parameters for a Weierstrass form Elliptic Curve.
![y^2 = x^3 + ax + b](https://render.githubusercontent.com/render/math?math=y%5E2%20%3D%20x%5E3%20%2B%20ax%20%2B%20b)

This curve is required to have the order equal to the prime of the Finite field over which it was defined.
![#E(\mathbb{F}_p) = p](https://render.githubusercontent.com/render/math?math=%23E(%5Cmathbb%7BF%7D_p)%20%3D%20p)

The sage script then performs Smart's attack on our anomalous curve in order to solve the Elliptic Curve Discrete Logarithm Problem, by reducing the Elliptic Curve to a ![$p$](https://render.githubusercontent.com/render/math?math=%24p%24)-adic Elliptic Curve, thus solving the ECDLP in linear time.

As the answer [here<sup>3</sup>](https://crypto.stackexchange.com/posts/70508/revisions) suggests, the edge case for Smart's attack is when the curve over ![\mathbb{Q}_p](https://render.githubusercontent.com/render/math?math=%5Cmathbb%7BQ%7D_p) that the algorithm lifts to, happens to be a canonical basis. Thus, no further information can be gained about the curve, leading the algorithm to fail at retrieving the private key (the solution to the discrete logarithm).

In order to generate an anomalous curve, however, one must pick a suitable discriminant as per the quoted references suggest. For this challenge, the discriminant ![D = 3](https://render.githubusercontent.com/render/math?math=D%20%3D%203) was chosen.

In order to find a suitable prime, one must look for a random number (![v](https://render.githubusercontent.com/render/math?math=v)) in a suitable range (in this challenge, bit sizes of >120 were chosen), which respects the following equality: ![4p = 1 + 3v^2](https://render.githubusercontent.com/render/math?math=4p%20%3D%201%20%2B%203v%5E2)

Once the prime is found, it is time to calculate the invariants of the Elliptic Curve. As the chosen discriminant entails a j-invariant equal to 0, we have to calculate the values for ![a](https://render.githubusercontent.com/render/math?math=a) and ![b](https://render.githubusercontent.com/render/math?math=b) with the following formulas:

![a = 27d\sqrt\[3\]{j\_invariant} \hspace{1cm} mod p](https://render.githubusercontent.com/render/math?math=a%20%3D%2027d%5Csqrt%5B3%5D%7Bj%5C_invariant%7D%20%5Chspace%7B1cm%7D%20mod%20p)
![b = 54d\sqrt{d(12^3 - j\_invariant)} \hspace{1cm} mod p](https://render.githubusercontent.com/render/math?math=b%20%3D%2054d%5Csqrt%7Bd(12%5E3%20-%20j%5C_invariant)%7D%20%5Chspace%7B1cm%7D%20mod%20p)

But since the j-invariant is equal to 0, a is also null.
Thus, our elliptic curve looks like this: ![y^2 = x^3 + b](https://render.githubusercontent.com/render/math?math=y%5E2%20%3D%20x%5E3%20%2B%20b)

We need, as a sanity check, to verify that the order of the curve is equal to the prime of the finite field. To do this without relying on Schoof-Elkies-Atkin (which SAGE uses by default when calling `order`), we can perform the following verification:

![\forall G \in E(\mathbb{F}_p), \hspace{1cm} if \hspace{1cm} p * G = (0 : 1 : 0)](https://render.githubusercontent.com/render/math?math=%5Cforall%20G%20%5Cin%20E(%5Cmathbb%7BF%7D_p)%2C%20%5Chspace%7B1cm%7D%20if%20%5Chspace%7B1cm%7D%20p%20*%20G%20%3D%20(0%20%3A%201%20%3A%200))

As the j-invariant is null and the curve is anomalous, the ![$p$](https://render.githubusercontent.com/render/math?math=%24p%24)-adic lifting of the curve will generate an edge case for Smart's attack.

The script receives the generator provided by the server and returns a random public key. This step is irrelevant, as the attack is already set for failure.


### Alternate solution

The alternate solution to this challenge involves no mathematics, and it can be found  ![here](https://hxp.io/blog/72/DEFCON-CTF-Quals-2020-notbefoooled/), a great case study for exploitation through unintended weaknesses.

