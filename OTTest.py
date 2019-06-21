#  gcc -shared -Wl,-soname,ot -o ot.so -fPIC OTClientServer.c ObliviousTransfer.c -lgmp
import ctypes
#import c library
alice =ctypes.cdll.LoadLibrary('./ot.so')
bob =ctypes.cdll.LoadLibrary('./ot2.so')

#overwrite default return type to char 
alice.GetPublicParams.restype = ctypes.c_char_p
alice.GetBlinedKey.restype = ctypes.c_char_p
alice.GetSharedTuple.restype = ctypes.c_char_p
alice.GetBValue.restype = ctypes.c_char_p
alice.GetEValue.restype = ctypes.c_char_p
alice.GetAValue.restype = ctypes.c_char_p
alice.GetBlinedR.restype = ctypes.c_char_p

bob.GetPublicParams.restype = ctypes.c_char_p
bob.GetBlinedKey.restype = ctypes.c_char_p
bob.GetSharedTuple.restype = ctypes.c_char_p
bob.GetBValue.restype = ctypes.c_char_p
bob.GetEValue.restype = ctypes.c_char_p
bob.GetAValue.restype = ctypes.c_char_p
bob.GetBlinedR.restype = ctypes.c_char_p



# Initiate the protocol
alice.InitOT(0) #0  is for initiater similar to Server
bob.InitOT(1) #1 for joiny like client

#get the security parameter
securityParam = alice.GetSecurityParam()

#Get the security params from initiater(Alice)
p = alice.GetPublicParams(0)
g0 = alice.GetPublicParams(1)
g1 = alice.GetPublicParams(2)
g2 = alice.GetPublicParams(3)

#Send & set the security params to Bob (p,g0,g1,g2 - only server to client)
bob.SetPublicParams(p,g0,g1,g2)

print "Bob P :", bob.GetPublicParams(0)
print "Bob G0 :", bob.GetPublicParams(1)
print "Bob G1 :", bob.GetPublicParams(2)
print "Bob G2 :", bob.GetPublicParams(3)

print "Alice P :", alice.GetPublicParams(0)
print "Alice G0 :", alice.GetPublicParams(1)
print "Alice G1 :", alice.GetPublicParams(2)
print "Alicc G2 :", alice.GetPublicParams(3)


#Get the blinded key
aliceBKey = alice.GetBlinedKey()
bobBKey = bob.GetBlinedKey()

print "Alice Blinded Key:", aliceBKey
print "Bob Blinded Key:", bobBKey

# Send & set Shared key (blindedkey -bothside)
alice.SetSharedKey(bobBKey)
bob.SetSharedKey(aliceBKey)

#Value both want to Compare
aliceC = 503554646650
bobC   = 503554646650

#Set the value to be compare
alice.SetCompareValue(aliceC)
bob.SetCompareValue(bobC)

#Get P,Q of Alice
aliceP = alice.GetSharedTuple(0)
aliceQ = alice.GetSharedTuple(1)

#Get P,Q of Bob
bobP = bob.GetSharedTuple(0)
bobQ = bob.GetSharedTuple(1)

print "Alice P:",aliceP,"Q:",aliceQ
print "Bob P:",bobP,"Q:",bobQ

# Send & set P,Q - both side
alice.SetSharedTuple(bobP,bobQ)
bob.SetSharedTuple(aliceP,aliceQ)

#Send B values- both side
aliceBi = []
bobBi = []
for i in range(securityParam):
    aliceBi.append(alice.GetBValue(i))
    bobBi.append(bob.GetBValue(i))
    alice.SetBValue(bob.GetBValue(i),i)
    bob.SetBValue(alice.GetBValue(i),i)

#P Should be validate with series of B
if(alice.ValidateKnowledgeOfB()):
    print "Alice knowledge of B Validated"
else:
    print "Alice knowledge of B not Validated"

if(bob.ValidateKnowledgeOfB()):
    print "Bob knowledge of B Validated"
else:
    print "Bob knowledge of B not Validated"

#Get Blined R value
aliceBR = alice.GetBlinedR()
bobBR = bob.GetBlinedR()

#send Blined R Value - both side
alice.SetSharedR(bobBR)
bob.SetSharedR(aliceBR)

# Send & validate each a,e values - both side
aliceAi = []
aliceEi = []
bobAi = []
bobEi = []
for i in range(securityParam):
    aliceAi.append(alice.GetAValue(i))
    aliceEi.append(alice.GetEValue(i))
    if(alice.ValidateKnowledge(aliceBi[i],aliceAi[i],aliceEi[i],i)):
        k =1
        # print "Alice knowledge of Secret", i, "passed"
    else:
        print "Alice knowledge of Secret",  i, "failed"
    
    bobAi.append(bob.GetAValue(i))

    bobEi.append(bob.GetEValue(i))
    if(bob.ValidateKnowledge(bobBi[i],bobAi[i],bobEi[i],i)):
        k =1
        # print "Bob knowledge of Secret", i, "passed"
    else:
        print "Bob knowledge of Secret", i, "failed"

    #Set a,e values once it's validate (should be request again for a particular a,e value if validation fails)
    alice.SetAEValue(bobAi[i],bobEi[i],i)
    bob.SetAEValue(aliceAi[i],aliceEi[i],i)


# Compute the Result
if(alice.GetResult()):
    print "Alice : Result is same"
else:
    print "Alice : Result is different"

if(bob.GetResult()):
    print "Bob : Result is same"
else:
    print "Bob : Result is different"