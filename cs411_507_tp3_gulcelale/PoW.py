import math
import random
import string
import warnings
import sympy
import DS
import Tx      
import os.path
import sys

from Crypto.Hash import SHA3_256
from Crypto.Hash import SHAKE128
import hashlib
import time
import hashlib
from struct import unpack, pack




def TakeMessage(filename, TxCnt):
	f = open ( filename,"r" )
	message = ""
	for i in range(TxCnt):
		message = message + f.readline()
		message = message + f.readline()
		message = message + f.readline()
		message = message + f.readline()
		message = message + f.readline()
		message = message + f.readline()
		message = message + f.readline()
		message = SHA3_256.new(message.encode('utf-8')).hexdigest() + "\n"
	f.close()
	return message



def CheckPow(p, q, g,PoWLen, TxCnt, filename):
	f = open ( filename,"r+" )
	lineList = f.readlines()
	f.seek(0)
	list = [0] * TxCnt 
	finalmessage = ""
	message = ""
	for i in range(TxCnt):
		message = ""
		for j in range(7):
			fileLine = f.readline()
			message = message + fileLine
			finalmessage = finalmessage + fileLine[:len(fileLine)-1] + "\n"
		list[i] = message
		#bir sonraki **** + bu buldugu transaction
	f.close()

	for k in range (len(list)):
		list[k] = SHA3_256.new(list[k].encode('utf-8'))


	i = TxCnt
	while(i != 1):
		newlist = [0] * int((i/2))
		newcounter = 0
		j = 0
		while( j < len(list)):
			h1 = list[j].digest()
			h2 = list[j+1].digest()
			newlist[newcounter] = (SHA3_256.new(h1+h2)) #hash
			j = j + 2
			newcounter = newcounter + 1
		i = i/2
		list = newlist
	
	Nonce = lineList[len(lineList)-1]
	Nonce = int(Nonce[7:])
	root = newlist[0].digest()
	hashed = (SHA3_256.new(root+(str(Nonce)+'\n').encode('UTF-8'))).hexdigest()
	#hashed = hash with message+nonce
	hashedVal = str(hashed)
	for i in range(PoWLen):
		if(hashedVal[i] != "0"):
			return ""
			# while (hashedVal[:PoWLen] != "0"*PoWLen):
			# 	Noncee = random.randint(2, pow(2,32))
			# 	hashedVal = SHA3_256.new((hashed + str(Noncee)).encode('utf-8')).hexdigest()
			# print(Noncee)
			# return hashedVal
	return hashedVal 

#take message in the filename and add with nonce and hash if powlen amount 0 exists in first chars then return hash value or return em
# def PoW(PoWLen, q, p, g, TxCnt, filename):
# 	file = open(filename,"r")
# 	file.seek(0)
# 	check = ""
# 	for i in range(TxCnt):
# 		check = check + '0'
# 	message = TakeMessage(filename, TxCnt)
# 	file.close()
# 	Nonce = random.randint(0,pow(2,32))
# 	hashed = SHA3_256.new((message+str(Nonce)).encode('utf-8')).hexdigest()
# 	#add nonce to message and hash together if first powlen amount chars are 0 then return the hash value
# 	while(str(hashed)[:4] != check):
# 		Nonce = random.randint(0,pow(2,32))
# 		hashed = SHA3_256.new((message+str(Nonce)).encode('utf-8')).hexdigest()
# 	return hashed


#message transaction(dosyadakiler bitcoin transaction yazıyo ya her biri ona kadar)
#filedan oku grupla 2serli olarak. 2^16 2^32 kalıcak sonra en tepedeki değere erisiyosun
#merkle tree hepsini hashle en sondakiyle  nonce'ı hashle o da esit midir 4.powlen 0 bits.
#ilk powcheck calısmıyo


def PoW(PoWLen, q, p, g, TxCnt, filename):
	f = open ( filename,"r" )
	lineList = f.readlines()
	f.seek(0)
	list = [0] * TxCnt
	finalmessage = ""
	message = ""
	for i in range(TxCnt):
		message = ""
		for j in range(7):
			fileLine = f.readline()
			message = message + fileLine[:len(fileLine)]
			finalmessage = finalmessage + fileLine[:len(fileLine)-1] + "\n"

		list[i] = message

	for k in range (len(list)):
		list[k] = SHA3_256.new(list[k].encode('utf-8'))


	i = TxCnt
	while(i != 1):
		newlist = [0] * int((i/2))
		newcounter = 0
		j = 0
		while( j < len(list)):
			h1 = list[j].digest()
			h2 = list[j+1].digest()
			newlist[newcounter] = (SHA3_256.new(h1+h2)) #hash
			j = j + 2
			newcounter = newcounter + 1
		i = i/2
		list = newlist

	# root = SHA3_256.new((newlist[0]).encode('utf-8')).hexdigest()
	# hashed = str(root)
	root = newlist[0].digest()
	hashedvalue = "1"*(PoWLen+1)
	while (hashedvalue[:PoWLen] != "0"*PoWLen and hashedvalue[PoWLen] != 0):
		Noncee = random.randint(2, pow(2,32))
		hashedvalue = (SHA3_256.new(root+(str(Noncee) + '\n').encode('UTF-8'))).hexdigest()
	f.close()
	return (finalmessage + "Nonce: " + str(Noncee))
# 	m = message.encode('utf-8')
# 	Nonce = 0
# 	hashed = SHA3_256.new()
	
	#add nonce to message and hash together if first powlen amount chars are 0 then return the hash value 

	#salt = random.randrange(k)
	#hashvalue = H(str(message) + str(salt)) 

# nonce = 0
# message = "gulo"

# message = message + str(nonce)
# while(nonce < 1000):
#     message = message + str(nonce)
#     h = SHA3_256.new(message)
#     h = h.digest()
#     print (h.hexdigest(),byteorder='big')
#     nonce = nonce + 1
# print("h:", h)




