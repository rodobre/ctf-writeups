import socket
import time
import random

# ------- Challenge specific ------- #
def launch_attack(P, Q, p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 8), [ZZ(t) for t in E.a_invariants()])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p * P_Qp
    p_times_Q = p * Q_Qp

    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()

    phi_P = -(x_P / y_P)
    phi_Q = -(x_Q / y_Q)
    k = phi_Q / phi_P

    return ZZ(k) % p

def attack(E, P, Q):
    private_key = launch_attack(P, Q, E.order())
    return private_key * P == Q

# ------- Curve construction ------- #

# -------- Helper function -------- #
def recvuntil(sock,delim = b'\n') :
    data = b""
    while not data.endswith(delim):
        data += sock.recv(1)
    return data
# -------- Helper function -------- #

a = 0
b = 0
p = 0
j_invar = 0
Q = None

# Get a range of [2**120, 2**121)
# Primes are going to be of > 240 bits, in order to fit the threshold
# Papers suggested for further reading
# https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session1-miele-paper.pdf
# http://www.monnerat.info/publications/anomalous.pdf
for i in range(2**120, 2**121):
    # We know that the prime must fit the equation
    # 4 * p = 1 + 3 * i^2     , where 3 is the chosen discriminant (D)
    koeff = 1 + 3 * i * i
    
    # Check if it is divisible by 4
    if koeff % 4 != 0:
        # Continue if it is not
        continue
    
    # Divide by 4
    p = koeff // 4
    if not is_prime(p):
        # If it is not prime, continue
        continue
        
    # For our discriminant, the j invariant is null
    j_invar = 0
    
    # Thus, following the formulas, we must initialize the parameters for our elliptic curve
    # a = 27 * d * cubic_root(j_invariant) mod p
    # b = 54 * d * sqrt(d * (12 ** 3 - j_invariant))
    # but j_invariant = 0 so a = 0
    
    a = 0
    b = (54 * 3 * pow(3 * 12**3, inverse_mod(2, p), p)) % p
    
    # Construct the elliptic curve
    E = EllipticCurve(GF(p), [a, b])
    
    # This curve usually has only one generator, safe to say this will be chosen by the server
    # Don't have a proof but experimental testing suggests this
    P = E.gen(0)
    
    # Grab a random point for order verification
    Q = E.random_point()
    
    # We check that the curve has order `p` if, by multiplying the generator by `p`, we obtain the point at infinity
    if p * P == E(0, 1, 0):
        # Success!
        print(E)
        print(a,b,p)
        print(E.order() - p)
        break

# Driver code. Connects to the socket, sends the parameters
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('notbefoooled.challenges.ooo', 5000))
s.send('{}\n'.format(a).encode('utf-8'))
s.send('{}\n'.format(b).encode('utf-8'))
s.send('{}\n'.format(p).encode('utf-8'))

# Receive the generator
print(recvuntil(s, b'generator'))
stt = s.recv(4096).decode('utf-8')

# Parse the generator
generator = stt.split(': ')[-1].split('\n')[0][1:-1].split(', ')
G = E(Integer(int(generator[0])), Integer(int(generator[1])))
print('generator', G)

# Here, it does not matter what point we provide
# The curve is anomalous and it is also a canonical lift, thus, the Smart attack will not succeed
# In order to succeed, proper implementation involves randomizing the lift
# As suggested in https://crypto.stackexchange.com/posts/70508/revisions
s.send('{}\n'.format(int(Q[0])).encode('utf-8'))
s.send('{}\n'.format(int(Q[1])).encode('utf-8'))

# Set timeout to compensate for server processing
s.settimeout(40)

# Print the flag
print(s.recv(4096))
print(s.recv(4096))
s.close()
