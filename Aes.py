import os
import sys
import math

class AES(object):
   	
    keySize = dict(SIZE_128=16)

    # S-box
    S_Box =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

    # Inverted S-box
    RS_Box = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

    # Rcon
    Rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39]

    # Her tur icin round key olustururak, ilk islemleri,
    # standart turu ve ileri aes islemlerini gerceklestirir.
    def op_aes(self, state, expandedKey, nbrRounds):
        state = self.addRound(state, self.roundKey(expandedKey, 0))
        i = 1
        while i < nbrRounds:
            state = self.aesRound(state, self.roundKey(expandedKey, 16*i))
            i += 1
        state = self.substitionBytes(state, False)
        state = self.shiftRows(state, False)
        state = self.addRound(state, self.roundKey(expandedKey, 16*nbrRounds))
        return state

    #Her tur icin round key olustururak, ilk islemleri,
    #standart turu ve ters aes islemlerini gerceklestirir
    def inv_main(self, state, expandedKey, nbrRounds):
        state = self.addRound(state, self.roundKey(expandedKey, 16*nbrRounds))
        i = nbrRounds - 1
        while i > 0:
            state = self.aesInv(state, self.roundKey(expandedKey, 16*i))
            i -= 1
        state = self.shiftRows(state, True)
        state = self.substitionBytes(state, True)
        state = self.addRound(state, self.roundKey(expandedKey, 0))
        return state

    #128 bitlik bir giris blogunu, belirtilen boyutta verilen anahtara gore sifreler
    def encrypt(self, iput, key, size):

        output = [0] * 16
        # round sayisi
        nbrRounds = 0
        # sifrelenecek blok
        block = [0] * 16
        if size == 16: nbrRounds = 10
        else: return None

        # genisletilmis keySize
        expandedKeySize = 16*(nbrRounds+1)

        for i in range(4):
            for j in range(4):
                block[(i+(j*4))] = iput[(i*4)+j]

        expandedKey = self.keyExpand(key, size, expandedKeySize)

        # expandedKey kullanarak blogun sifrelenmesi
        block = self.op_aes(block, expandedKey, nbrRounds)

        for k in range(4):
        	# satirlar uzerinde ilerlenme
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output

    # 128 bitlik bir giris blogunu, belirtilen boyutta verilen anahtara gore desifreler
    def decrypt(self, iput, key, size):
        output = [0] * 16
        # round sayisi
        nbrRounds = 0
        # desifrelenecek blok
        block = [0] * 16
        if size == 16: nbrRounds = 10
        else: return None

        # genisletilmis keySize
        expandedKeySize = 16*(nbrRounds+1)

        # sutunlar uzerinde ilerleme
        for i in range(4):
        	# satirlar uzerinde ilerleme
            for j in range(4):
                block[(i+(j*4))] = iput[(i*4)+j]
        # anahtar genisletilmesi
        expandedKey = self.keyExpand(key, size, expandedKeySize)
        # key kullanarak desifreleme
        block = self.inv_main(block, expandedKey, nbrRounds)
        for k in range(4):
        	# satirlar uzerinde ilerlenir
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output


    def SBox(self,num):
    	#Verilen sayinin SBox degerini getirir
        return self.S_Box[num]

    def SBoxInv(self,num):
    	#Verilen sayinin Inverted S-Box degerini getirir
        return self.RS_Box[num]

    def RconVal(self, num):
    	#Verilen sayinin RCon degerini getirir
        return self.Rcon[num]

    def Op_Rotate(self, word):
    	#anahtar program dondurme islemi.
        return word[1:] + word[:1]

    def schedule(self, word, iteration):
    	"""Anahtar program cekirdegi."""
        word = self.Op_Rotate(word)
        # 32 bit sozcugun 4 parcasinin tumune S-Box ikamesi uygulanir
        for i in range(4):
            word[i] = self.SBox(word[i])
        # i ile rcon isleminin ciktisinin ilk parcaya XOR lanmasi
        word[0] = word[0] ^ self.RconVal(iteration)
        return word

    def keyExpand(self, key, size, expandedKeySize):
        """Anahtar genisletmesi.

        expandedKey, yeterince buyuk bir karakter listesidir,
        key, genisletilmemis anahtardir.
        """
        # byte cinsinden gecerli genisletilmis keySize
        currentSize = 0
        rconIteration = 1
        expandedKey = [0] * expandedKeySize

        for j in range(size):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expandedKeySize:
        	#onceki 4 byte gecici t degerine atanir
            t = expandedKey[currentSize-4:currentSize]

            if currentSize % size == 0:
                t = self.schedule(t, rconIteration)
                rconIteration += 1
            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ \
                        t[m]
                currentSize += 1

        return expandedKey

    def addRound(self, state, roundKey):
    	"""Yuvarlak anahtari duruma ekler (XOR)."""
        for i in range(16):
            state[i] ^= roundKey[i]
        return state

    def roundKey(self, expandedKey, roundKeyPointer):
        roundKey = [0] * 16
        for i in range(4):
            for j in range(4):
                roundKey[j*4+i] = expandedKey[roundKeyPointer + i*4 + j]
        return roundKey

    def galois_mult(self, a, b):
    	"""8 bitlik karakterlerin a ve b Galois carpimi."""
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

	# durum degerini SBox icin indeks olarak kullanarak durumdaki 
	# tum degerleri SBox'daki degerle degistirin
    def substitionBytes(self, state, isInv):

        if isInv: getter = self.SBoxInv
        else: getter = self.SBox
        for i in range(16): state[i] = getter(state[i])
        return state

    # 4 satir uzerinde yineleyin ve bu satirla shiftRow () ogesini cagirin
    def shiftRows(self, state, isInv):

        for i in range(4):
            state = self.shiftRow(state, i*4, i, isInv)
        return state

    # her yineleme satiri 1 sola kaydirir
    def shiftRow(self, state, statePointer, nbr, isInv):

        for i in range(nbr):
            if isInv:
                state[statePointer:statePointer+4] = \
                        state[statePointer+3:statePointer+4] + \
                        state[statePointer:statePointer+3]
            else:
                state[statePointer:statePointer+4] = \
                        state[statePointer+1:statePointer+4] + \
                        state[statePointer:statePointer+1]
        return state

    # 4x4 matrisinin galois carpimi
    def mixColumns(self, state, isInv):
        for i in range(4):
        	# 4 satiri bolerek bir sutun olusturun
            column = state[i:i+16:4]
            # mixColumn'u bir sutuna uygulayin
            column = self.mixColumn(column, isInv)
            state[i:i+16:4] = column

        return state

    # 4x4 matrisinin 1 sutununun galois carpimi
    def mixColumn(self, column, isInv):
        if isInv: mult = [14, 9, 13, 11]
        else: mult = [2, 1, 1, 3]
        cpy = list(column)
        g = self.galois_mult

        column[0] = g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^ \
                    g(cpy[2], mult[2]) ^ g(cpy[1], mult[3])
        column[1] = g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^ \
                    g(cpy[3], mult[2]) ^ g(cpy[2], mult[3])
        column[2] = g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^ \
                    g(cpy[0], mult[2]) ^ g(cpy[3], mult[3])
        column[3] = g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^ \
                    g(cpy[1], mult[2]) ^ g(cpy[0], mult[3])
        return column

    # Ileri roundun 4 islemini sirayla uygular
    def aesRound(self, state, roundKey):
        state = self.substitionBytes(state, False)
        state = self.shiftRows(state, False)
        state = self.mixColumns(state, False)
        state = self.addRound(state, roundKey)
        return state

    # inverse turun 4 islemini sirayla uygular
    def aesInv(self, state, roundKey):
        state = self.shiftRows(state, True)
        state = self.substitionBytes(state, True)
        state = self.addRound(state, roundKey)
        state = self.mixColumns(state, True)
        return state

class AESModeOfOperation(object):

    aes = AES()

    # desteklenen calisma modlari
    modeOfOperation = dict(OFB=0, CBC=2)

    # 16 karakterlik bir dizeyi bir sayi dizisine donusturur
    def convertString(self, string, start, end, mode):
        if end - start > 16: end = start + 16
        if mode == self.modeOfOperation["CBC"]: ar = [0] * 16
        else: ar = []

        i = start
        j = 0
        while len(ar) < end - start:
            ar.append(0)
        while i < end:
            ar[j] = ord(string[i])
            j += 1
            i += 1
        return ar

    # Sifreleme Modu
    # stringIn - Input String
    # mode - mode of type modeOfOperation
    # hexKey - a hex key of the bit length size
    # size - the bit length of the key
    # hexIV - the 128 bit hex Initilization Vector
    def encrypt(self, stringIn, mode, key, size, IV):
        if len(key) % size:
            return None
        if len(IV) % 16:
            return None
        # Aes input outputu
        plaintext = []
        iput = [0] * 16
        output = []
        # sifrelenmis metin
        ciphertext = [0] * 16
        cipherOut = []
        firstRound = True
        if stringIn != None:
            for j in range(int(math.ceil(float(len(stringIn))/16))):
                start = j*16
                end = j*16+16
                if  end > len(stringIn):
                    end = len(stringIn)
                plaintext = self.convertString(stringIn, start, end, mode)
                if mode == self.modeOfOperation["OFB"]:
                    if firstRound:
                        output = self.aes.encrypt(IV, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(iput, key, size)
                    for i in range(16):
                        if len(plaintext)-1 < i:
                            ciphertext[i] = 0 ^ output[i]
                        elif len(output)-1 < i:
                            ciphertext[i] = plaintext[i] ^ 0
                        elif len(plaintext)-1 < i and len(output) < i:
                            ciphertext[i] = 0 ^ 0
                        else:
                            ciphertext[i] = plaintext[i] ^ output[i]
                    for k in range(end-start):
                        cipherOut.append(ciphertext[k])
                    iput = output
                elif mode == self.modeOfOperation["CBC"]:
                    for i in range(16):
                        if firstRound:
                            iput[i] =  plaintext[i] ^ IV[i]
                        else:
                            iput[i] =  plaintext[i] ^ ciphertext[i]
                    firstRound = False
                    ciphertext = self.aes.encrypt(iput, key, size)
                    # CBC icin dolgu nedeniyle her zaman 16 bayt
                    for k in range(16):
                        cipherOut.append(ciphertext[k])
        return mode, len(stringIn), cipherOut
    
    # Desifreleme
    # cipherIn - Encrypted String
    # originalsize - The unencrypted string length - required for CBC
    # mode - mode of type modeOfOperation
    # key - a number array of the bit length size
    # size - the bit length of the key
    # IV - the 128 bit number array Initilization Vector
    def decrypt(self, cipherIn, originalsize, mode, key, size, IV):
        if len(key) % size:
            return None
        if len(IV) % 16:
            return None
        # AES input outputu
        ciphertext = []
        iput = []
        output = []
        plaintext = [0] * 16
        chrOut = []
        firstRound = True
        if cipherIn != None:
            for j in range(int(math.ceil(float(len(cipherIn))/16))):
                start = j*16
                end = j*16+16
                if j*16+16 > len(cipherIn):
                    end = len(cipherIn)
                ciphertext = cipherIn[start:end]
                if mode == self.modeOfOperation["OFB"]:
                    if firstRound:
                        output = self.aes.encrypt(IV, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(iput, key, size)
                    for i in range(16):
                        if len(output)-1 < i:
                            plaintext[i] = 0 ^ ciphertext[i]
                        elif len(ciphertext)-1 < i:
                            plaintext[i] = output[i] ^ 0
                        elif len(output)-1 < i and len(ciphertext) < i:
                            plaintext[i] = 0 ^ 0
                        else:
                            plaintext[i] = output[i] ^ ciphertext[i]
                    for k in range(end-start):
                        chrOut.append(chr(plaintext[k]))
                    iput = output
                elif mode == self.modeOfOperation["CBC"]:
                    output = self.aes.decrypt(ciphertext, key, size)
                    for i in range(16):
                        if firstRound:
                            plaintext[i] = IV[i] ^ output[i]
                        else:
                            plaintext[i] = iput[i] ^ output[i]
                    firstRound = False
                    if originalsize is not None and originalsize < end:
                        for k in range(originalsize-start):
                            chrOut.append(chr(plaintext[k]))
                    else:
                        for k in range(end-start):
                            chrOut.append(chr(plaintext[k]))
                    iput = ciphertext
        return "".join(chrOut)


def appendPKCS7(s):
	# PKCS7 dolgusu tarafindan 16 baytlik bir carpana kadar dondurulur
    numpads = 16 - (len(s)%16)
    return s + numpads*chr(numpads)

def stripPKCS7(s):
	# donus PKCS7 dolgusundan arindirilir
    if len(s)%16 or not s:
        raise ValueError("String of len %d can't be PCKS7-padded" % len(s))
    numpads = ord(s[-1])
    if numpads > 16:
        raise ValueError("String ending with %r can't be PCKS7-padded" % s[-1])
    return s[:-numpads]

def encryptData(key, data, mode=AESModeOfOperation.modeOfOperation["CBC"]):

	# "verileri" "anahtar" kullanarak sifreler
    # "anahtar" bir byte dizesi olmalidir.
    # dondurulen sifreleme, baslatma vektorunun basina eklenen bir byte dizesidir.

    key = map(ord, key)
    if mode == AESModeOfOperation.modeOfOperation["CBC"]:
        data = appendPKCS7(data)
    keysize = len(key)
    assert keysize in AES.keySize.values(), 'invalid key size: %s' % keysize
    # rastgele verileri kullanarak yeni bir iv olusturulur
    iv = [ord(i) for i in os.urandom(16)]
    moo = AESModeOfOperation()
    (mode, length, ciph) = moo.encrypt(data, mode, key, keysize, iv)
    # Dolgu ile orijinal uzunlugun bilinmesine gerek yoktur.
    #  Orijinal mesaj uzunlugunu saklamak kotu bir fikirdir.
    return ''.join(map(chr, iv)) + ''.join(map(chr, ciph))

def decryptData(key, data, mode=AESModeOfOperation.modeOfOperation["CBC"]):
    #"verileri" "anahtar" kullanarak desifreler
    #"anahtar" bir byte dizesi olmalidir.
    #"veriler", baslangic vektorunun basina sira degerleri dizesi olarak eklenmelidir.
   
    key = map(ord, key)
    keysize = len(key)
    assert keysize in AES.keySize.values(), 'invalid key size: %s' % keysize
    # iv ilk 16 byttetir.
    iv = map(ord, data[:16])
    data = map(ord, data[16:])
    moo = AESModeOfOperation()
    decr = moo.decrypt(data, None, mode, key, keysize, iv)
    if mode == AESModeOfOperation.modeOfOperation["CBC"]:
        decr = stripPKCS7(decr)
    return decr

def randomKeyGenerator(keysize):
    #Rastgele uzunluk "anahtar boyutu" verilerinden bir anahtar olusturur.   
    
    if keysize != 16:
        emsg = 'Invalid keysize, %s. Should be one of (16).'
        raise ValueError, emsg % keysize
    return os.urandom(keysize)


def Test(cleartext, keysize=16, modeName = "CBC"):

    print("Acik Metin: %s" % cleartext)
    key =  randomKeyGenerator(keysize)
    print 'Anahtar: ', [ord(x) for x in key]
    mode = AESModeOfOperation.modeOfOperation[modeName]
    cipher = encryptData(key, cleartext, mode)
    print 'Sifrelenmis Metin:', [ord(x) for x in cipher]
    decr = decryptData(key, cipher, mode)
    print 'Desifrelenmis Metin:', decr
    
    
if __name__ == "__main__":

	print
	print("============================AES Test1================================")
	print

	mod = AESModeOfOperation()

	message = "Bu test metnidir"

	print("Acik Metin: %s" % message)

	key = [181,144,56,201,107,233,211,157,179,206,87,216,185,82,145,58]
	print("Anahtar: %s" % key)
	iv = [120,65,158,250,96,113,77,128,254,111,230,99,92,145,78,91]

	mode, orig_len, ciph = mod.encrypt(message, mod.modeOfOperation["CBC"], key, 16, iv)

	print("Sifrelenmis Metin: %s" % ciph)

	decr = mod.decrypt(ciph, orig_len, mode, key,16, iv)

	print("Desifrelenmis Metin: %s" % decr)

	print
	print("=============================AES Test2=================================")
	print

	mod = AESModeOfOperation()

	message = "Merhabalar Dunya"
	print("Acik Metin: %s" % message)

	key = [181,144,56,201,107,233,211,157,179,206,87,216,185,82,145,58]
	print("Anahtar: %s" % key)
	iv = [120,65,158,250,96,113,77,128,254,111,230,99,92,145,78,91]

	mode, orig_len, ciph = mod.encrypt(message, mod.modeOfOperation["OFB"], key, 16, iv)

	print("Sifrelenmis Metin: %s" % ciph)

	decr = mod.decrypt(ciph, orig_len, mode, key,mod.aes.keySize["SIZE_128"], iv)

	print("Desifrelenmis Metin: %s" % decr)


	print
	print("==========================CBC Mode Testi===============================")
	print

	Test(message, 16, "CBC")	

	print
	print("==========================OFB Mode Testi===============================")
	print

	Test(message, 16, "OFB")	

 



    