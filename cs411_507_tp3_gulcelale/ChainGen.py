import math
import random
import string
import warnings
import os.path
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import ECDSA     
import ChainGen       

TxLen = 9
def chunk(l, n):
	#divides txt to 9 
	count = 0
	line = ""
	ls = []
	for i in l:
		if(count < 9): 
			line += i
			count += 1
		else:
			ls.append(line)
			line = ""
	return ls

def PoW(PoWLen, TxCnt, block_candidate):
	prev_pow = block_candidate[len(block_candidate)-1]
	block_candidate = block_candidate[:len(block_candidate)]
	ls = chunk(block_candidate, TxCnt )

	root = MerkleTree(TxCnt,ls)
	hashedvalue = "1"*(PoWLen+1)
	while (hashedvalue[:PoWLen] != "0"*PoWLen and hashedvalue[PoWLen] != 0):
		Noncee = random.randint(2, pow(2,32))
		hashedvalue = (SHA3_256.new(root + prev_pow.encode('UTF-8') + (str(Noncee) + '\n').encode('UTF-8'))).hexdigest()
	block_candidate.append(prev_pow)
	lst = "".join(block_candidate)                                                                                                                                                                                                            
	return (lst + "Nonce: " + str(Noncee))

def MerkleTree(TxCnt,transaction):
    hashTree = []
    TxLen = len(transaction) // 9 
    for i in range(0,TxCnt):
        transaction = "".join(transaction[i*TxLen:(i+1)*TxLen])
        hashTree.append(SHA3_256.new(transaction.encode('UTF-8')).digest())
    t = TxCnt
    j = 0
    while(t>1):
        for i in range(j,j+t,2):
            hashTree.append(SHA3_256.new(hashTree[i]+hashTree[i+1]).digest())
        j += t
        t = t>>1

    H_r = hashTree[2*TxCnt-2]
    #returns root 
    return H_r	

def AddBlock2Chain(PoWLen, TxCnt, block_candidate, PrevBlock):
	if(PrevBlock == ""): 
	    PrevPoW = "00000000000000000000"
	
	else:

		#for previous block
	    
		hashTree = []
		for i in range(0,TxCnt):
			transaction = "".join(PrevBlock[i*TxLen:(i+1)*TxLen])
			hashTree.append(SHA3_256.new(transaction.encode('UTF-8')).digest())
		t = TxCnt
		j = 0
		while(t>1):
			for i in range(j,j+t,2):
				hashTree.append(SHA3_256.new(hashTree[i]+hashTree[i+1]).digest())
			j += t
			t = t>>1

		H_r = hashTree[2*TxCnt-2]	    

##################
		PrevPoW = PrevBlock[-2][14:-1]
		PrevPoW = PrevPoW.encode('UTF-8')
		Prevnonce = int(PrevBlock[-1][7:-1])
		digest = H_r + PrevPoW + Prevnonce.to_bytes((Prevnonce.bit_length()+7)//8, byteorder = 'big')
		PrevPoW = SHA3_256.new(digest).hexdigest()
	    
	    #if(PrevPoW[0:PoWLen] != "0"*PoWLen):
	    #	return ""
	    
	
	#for candidate block
	#H_r = MerkleTree(TxCnt,block_candidate)
	hashTree = []

	for i in range(0,TxCnt):
		transaction = "".join(block_candidate[i*TxLen:(i+1)*TxLen])
		hashTree.append(SHA3_256.new(transaction.encode('UTF-8')).digest())
	t = TxCnt
	j = 0
	while(t>1):
		for i in range(j,j+t,2):
			hashTree.append(SHA3_256.new(hashTree[i]+hashTree[i+1]).digest())
		j += t
		t = t>>1

	H_r = hashTree[2*TxCnt-2]
	#PrevPoW = PrevBlock[-2][14:-1]	
	#PrevPoW = PrevPoW.encode('UTF-8')
	#digest = H_r + PrevPoW + r.to_bytes((r.bit_length()+7)//8, byteorder = 'big')
	#hashedvalue = SHA3_256.new(digest).hexdigest()

	while True:
		Noncee = random.randint(0, 2**128)
		digest = H_r + PrevPoW.encode('UTF-8')  + Noncee.to_bytes((Noncee.bit_length()+7)//8, byteorder = 'big')
		hashedvalue = SHA3_256.new(digest).hexdigest()
		if(hashedvalue[0:PoWLen]=="0"*PoWLen):
			block_candidate = "".join(block_candidate)
			#PrevPoW.decode('utf-8')
			block_candidate = block_candidate + "Previous PoW: " + PrevPoW +"\n"
			block_candidate = block_candidate + "Nonce: " + str(Noncee) + "\n"
			break
	return block_candidate, PrevPoW







