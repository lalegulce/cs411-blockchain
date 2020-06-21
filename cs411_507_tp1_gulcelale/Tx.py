import warnings
import math
import timeit
import random
import pyprimes
import sympy
import string
import os
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHAKE128
import hashlib

import DS

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    if a < 0:
        a = a+m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
 

def random_prime(bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        p = random.randrange(2**(bitsize-1), 2**bitsize-1)
        chck = sympy.isprime(p)
    warnings.simplefilter('default')    
    return p

def large_DL_Prime(q, bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        k = random.randrange(2**(bitsize-1), 2**bitsize-1)
        p = k*q+1
        chck = sympy.isprime(p)
    warnings.simplefilter('default')    
    return p

def Param_Generator(qsize, psize):
    q = random_prime(qsize)
    p = large_DL_Prime(q, psize)
    tmp = (p-1)//q
    g = 1
    while g == 1:
        alpha = random.randrange(1, p)
        g = pow(alpha, tmp, p)
    return q, p, g

def KeyGen(q, p ,g):
	pvtkey = random.randint(1, q-2) #private key chosen randomly
	beta = pow(g, pvtkey, p) #public key

	return pvtkey, beta


def SignGen(message, q, p, g, pvtkey):
	#h=SHA3_256.new(message.encode('utf8'))
	h=SHA3_256.new(message)
	h = int.from_bytes(h.digest(),byteorder='big') % q
	#h = int.from_bytes(hashlib.sha256(message.encode('utf-8')).hexdigest(), byteorder='big') % q # h = H(message)
	k = random.randint(1, q-1) #random, secret integer k 
	r = pow(g, k, p) % q 	#r=(g^k(mod p)) (mod q)
	s = ((pvtkey * r) - (k * h))%q #s=k^−1(h + ar) (mod q)

#(r,s) is the signature for the message
#sends (r, s) and m for verifying
	return s , r


def SignVer(message, s ,r , q, p, g, beta):
	#h=SHA3_256.new(message.encode('utf8'))
	h = int.from_bytes(SHA3_256.new(message).digest(),byteorder='big') %q
	#h = int.from_bytes(hashlib.sha256(message.encode('utf-8')).hexdigest(), byteorder='big') % q # h = H(message)
	v = modinv(h, q)
	z1 = (s * v) % q
	z2 = (r * v) % q
	u = ((modinv(pow(g, z1,p),p) * pow(beta, z2, p)) % p) % q
	if(u==r):
		return 0
		#verified
	else:
		return 1


def gen_random_tx(q,p,g):
	SerialNum = random.randint(2**(127),2**182-1)
	payerPriv, payerPublic = KeyGen(q,p,g)
	payeePriv, payeePublic = KeyGen(q,p,g)
	while(payerPublic == payeePublic):
		payeePriv, payeePublic = KeyGen(q,p,g)
	
	Amount = random.randint(1,1000000)

	#information of the payment
	txt = "*** Bitcoin transaction ***"
	txt = txt + "\n" + "Serial number: " + str(SerialNum) + "\n"
	txt = txt + "Payer public key (beta): " + str(payerPublic) + "\n" 
	txt = txt + "Payee public key (beta): " + str(payeePublic) + "\n" 
	txt = txt + "Amount: " + str(Amount) + "\n"
	message = txt.encode('utf-8')
	s, r = SignGen(message,q,p,g,payerPriv)
	txt = txt + "Signature (s): " + str(s) + "\n" 
	txt = txt + "Signature (r): " + str(r) + "\n"
	#print(txt)
	#return SerialNum
	return txt


# def CheckBlockofTransactions():
# 	params = open("pubparams.txt","r")
# 	if(params.mode!= 'r'):
# 		print ("parameter file is not found")
# 	q = params.readline()
# 	p = params.readline()
# 	g = params.readline()
# 	params.close()
# 	count = 0
# 	tracker = 0

# 	f = open("transaction.txt","r")
# 	if(f.mode!= 'r'):  #checks if file is opened
# 		print ("transaction file is not found")

# 	for line in f: #traverse lines in file
# 		if(tracker == count and tracker > 0): #checks if I finished transaction informations (count part in *, tracker part in r value)
# 			#SignVer(message, s ,r , q, p, g, beta):
# 			if(SignVer(SerialNum,s,r,q,p,g,payerPublic)==0): #returns 0 when u==r
# 				print("Transaction ",tracker," Verified")
# 			else:
# 				print("Transaction ",tracker," not Verified")
# 		if(line.find('*') >= 0): #first line of a transaction
# 			print ("Transaction occured")
# 			count = count + 1
# 		else:							#reading lines and getting values linebyline
# 			if(line.find("Serial")):
# 				fields = line.split(": ") #splits to two parts as name and value
# 				fieldName = fields[0] #we do not care about fieldname / no need to hold it (we can struct an object which holds all values)
# 				SerialNum = fields[1]
# 			elif(line.find("Payer public") >= 0): #find function returns -1 if not found
# 				fields = line.split(": ")
# 				fieldName = fields[0]
# 				payerPublic = int(fields[1])
# 			elif(line.find("Payee public") >= 0):
# 				fields = line.split(": ")
# 				fieldName = fields[0]
# 				payeePublic = it(fields[1])
# 			elif(line.find("Signature (s)")>= 0):
# 				fields = line.split(": ")
# 				fieldName = fields[0]
# 				s = int(fields[1])
# 			elif(line.find("Signature (r)")>= 0):
# 				fields = line.split(": ")
# 				fieldName = fields[0]
# 				r = int(fields[1])
# 				tracker = tracker + 1
# 	f.close()



# q, p, g = Param_Generator(224,2048)
# pvtkey, h = KeyGen(q, p ,g)
# #print(q, p , g, pvtkey, h)
# message = str(gen_random_tx(q,p,g))

# s, r = SignGen(message, q, p, g, pvtkey)

# SignVer(message, s ,r , q, p, g, h)




