import math
import timeit
import random
import pyprimes
import warnings	
import hashlib
import sympy
import linecache
import string
from Crypto.Hash import SHA3_256 	
from Crypto.Hash import SHAKE128
from Crypto.PublicKey import RSA
from Crypto import Random
from verify import Match

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
    chck2 = False
    while (chck == False) or (chck2 == False):
    	chck = False
    	chck2 = False
    	k = random.randrange(2**(bitsize-1), 2**bitsize-1)
    	p = k*q+1
    	chck = sympy.isprime(p)
    	chck2= (p.bit_length() == 2048)
    warnings.simplefilter('default')
    return p

def Param_Generator(qsize, psize): #DSA setup
    q = random_prime(qsize)
    p = large_DL_Prime(q, psize-qsize)
    tmp = (p-1)//q
    g = 1
    while g == 1:
        alpha = random.randrange(1, p)
        g = pow(alpha, tmp, p)
    return q, p, g

#print(Param_Generator(224,2048))

#q=21033988423228858762274567886518993635758355877139143016203296708423
#p=679370715999318643884626724892268938446017141213837922159089378467716527154655311865457012517842684776146311951437979233439424729734619654888351104069251101405183358756284488167031762059514834548152681435898418253194168974409115717861557326423267681786151501692192787674101272306132690083988491372599978572337219676655509321381881456083304128560701856173449473164298873308508275035875398335739879743750914437871638150722064093586250997922832090126146989065617122995042386207655407709784240410501313184782814653535022850844653661968053749971627801089360108260394830869249462959670265353546951848416669227458141380667775547448266834660147510478744144003446926296267644760290292362371347
#g=386535785614607392466046534617255952543162883156874161807700747719721741689244351352880799205332876437001157731213740569641201016171851774903709167788242290698303257256207855567004530399956666365190568003553992806077229100400047535580017923355625353149807714193228310179229329730079440794699928566038242177868352613497464124364870444794530161554902461598606007442185749321534854701547971816551069706066094105545887192869503033087270735868475804328170320263501153064262782858270726931229903388527403091775178201773754741887863836234658431437177454786528525294645225206126261168950181480488294692871969400865198217463941435191453864886796289181528736689970403572411486589452238174791504


# h = hashlib.sha256(message.encode('utf-8')).hexdigest()
# print("Hash h: " + repr(h) + "\n")

def KeyGen(q, p ,g):
	pvtkey = random.randint(1, q-2) #private key(alpha) chosen randomly 
	beta = pow(g, pvtkey, p) #public key

	return pvtkey, beta

def random_string(string_Length):
    letter = string.ascii_lowercase
    finalString = ''
    for j in range(string_Length):
        finalString = finalString.join(random.choice(letter))
    return finalString


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



def checkDSparams(q, p, g):
    check = 0
    warnings.simplefilter('ignore')
    #check = pyprimes.isprime(q)   # not fast enough
    check = sympy.isprime(q)
    warnings.simplefilter('default')
    if check == False: return -1
    
    warnings.simplefilter('ignore')
    #check = pyprimes.isprime(p)    # not fast enough
    check = sympy.isprime(p)
    warnings.simplefilter('default')
    if check == False: return -2
   
    if((p-1)%q != 0): return -3

    k = (p-1)//q
    x = pow(g, k, p)
    if (x==1): return -4
    y = pow(g,q,p)
    if (y!=1): return -4

    if p.bit_length() != 2048: return -5

    if q.bit_length() != 224: return -6
    return 0


#reads q, p, g from "pubparams.txt" if exists
#otherwise, generate public parameters and write them to "pubparams.txt" 
def GenerateOrRead(filename):
    file = open(filename, "r")
    file.seek(0)
    if(file.mode != 'r'):
        newf.open("pubparam.txt","w+")
        q, p ,g = Param_Generator(224, 2048)
        file.write( str(q) + '\n' + str(p) + '\n' + str(g))
        newf.close()
        return q, p, g
    else:
        q = int(file.readline())
        p = int(file.readline())
        g = int(file.readline())
        if(checkDSparams(q,p,g) != 0):
            file.close()
            q,p,g = Param_Generator(224, 2048)
            return q, p, g
        file.close()
        return q, p, g 


# message = "CS411 Project"
# q, p, g = Param_Generator(224,2048)
# pvtkey, h = KeyGen(q, p ,g)
# print("q =",q ,"p =", p ,"g =", g,"pvtkey =", pvtkey,"h =", h)
# r, s = SignGen(message, q, p, g, pvtkey)
# SignVer(message, s ,r , q, p, g, h)


