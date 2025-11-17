from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
import os
import random
from datetime import date
import ecdsa
from hashlib import sha256
import pickle
import re
import pyaes, pbkdf2, binascii, os, secrets
import pymysql
import smtplib
import hashlib
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
from PIL import Image

global username, otp, email

#function to get ECC assymetric keys
def getECCKeys():
    if os.path.exists("SecurityApp/static/keys/pvt.key"):
        with open("SecurityApp/static/keys/pvt.key", 'rb') as f:
            private_key = f.read()
        f.close()
        with open("SecurityApp/static/keys/pri.key", 'rb') as f:
            public_key = f.read()
        f.close()
        private_key = private_key.decode()
        public_key = public_key.decode()
    else:
        secret_key = generate_eth_key()
        private_key = secret_key.to_hex()  # hex string
        public_key = secret_key.public_key.to_hex()
        with open("SecurityApp/static/keys/pvt.key", 'wb') as f:
            f.write(private_key.encode())
        f.close()
        with open("SecurityApp/static/keys/pri.key", 'wb') as f:
            f.write(public_key.encode())
        f.close()
    return private_key, public_key

#function to get AES symmetric keys
def generateKeys():
    if os.path.exists("SecurityApp/static/keys/key.pckl"):
        f = open("SecurityApp/static/keys/key.pckl", 'rb')
        keys = pickle.load(f)
        f.close()
        secret_key = keys[0]
        private_key = keys[1]
    else:
        secret_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256) # The default is sha1
        private_key = secret_key.get_verifying_key()
        keys = [secret_key, private_key]
        f = open("SecurityApp/static/keys/key.pckl", 'wb')
        pickle.dump(keys, f)
        f.close()
    private_key = private_key.to_string()[0:32]    
    return private_key

def encryptAES(plaintext, key): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decryptAES(enc, key): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

#ECC based data encryption
def ECCEncrypt(plainText, public_key):
    ecc_encrypt = encrypt(public_key, plainText)
    return ecc_encrypt

#ECC based data decryption
def ECCDecrypt(encrypt, private_key):
    ecc_decrypt = decrypt(private_key, encrypt)
    return ecc_decrypt

def generateBits(message):
    msg_bit = []
    for bit in message:
        binary_bit = format(ord(bit), '08b')
        msg_bit.extend([int(b) for b in binary_bit])
    return msg_bit

def bits2msg(msg_bits):
    msg = []
    for i in range(0, len(msg_bits), 8):
        byte = "".join(map(str, msg_bits[i:i + 8]))
        msg.append(chr(int(byte, 2)))
    return "".join(msg)

def hideMessage(filename, secret_message):
    cover_image = Image.open(filename).convert("RGB")
    width, height = cover_image.size
    message_bits = generateBits(secret_message)
    bit_index = 0
    #embed bits horizontal
    for y in range(height):
        for x in range(width):
            if bit_index < 100:
                r, g, b = cover_image.getpixel((x, y))
                # if color detected then embed messaage horizontal
                r = (r & ~1) | message_bits[bit_index]
                cover_image.putpixel((x, y), (r, g, b))
                bit_index += 1
            else:
                break
        if bit_index >= len(message_bits):
            break
    #embed bits vertical
    for x in range(width):
        for y in range(height):
            if bit_index < len(message_bits):
                r, g, b = cover_image.getpixel((x, y))
                # if B is two coloured then embed message
                g = (g & ~1) | message_bits[bit_index]
                cover_image.putpixel((x, y), (r, g, b))
                bit_index += 1
            else:
                break
        if bit_index >= len(message_bits):
            break
    return cover_image

def extractMessage(filepath):
    cover_image = Image.open(filepath)
    width, height = cover_image.size
    extracted_bits = []
    potential_message = ""
    for y in range(height):
        for x in range(width):
            #inspect colour in each pixel
            r, g, b = cover_image.getpixel((x, y))
            #if two colour then extract bit
            extracted_bits.append(r & 1)
            if len(extracted_bits) < 100:
                potential_message = bits2msg(extracted_bits[:len(extracted_bits)//8*8]) # Only consider full bytes
            else:
                break
        print(len(extracted_bits))    
        if len(extracted_bits) >= 100:
            potential_message = potential_message.split("#")[0]
            break
    for x in range(width):
        for y in range(height):
            r, g, b = cover_image.getpixel((x, y))
            extracted_bits.append(g & 1)
            if len(extracted_bits) > 1000:
                potential_message = bits2msg(extracted_bits[:len(extracted_bits)//8*8])
                if "#" in potential_message:
                    potential_message = potential_message.split("#")[0]
                    break
        if "#" in potential_message:
            potential_message = potential_message.split("#")[0]
            break    
    return potential_message

def ImageStegAction(request):
    if request.method == 'POST':
        global username
        message = request.POST.get('t1', False)
        message += " #"
        filename = request.FILES['t2'].name
        image_data = request.FILES['t2'].read()
        if os.path.exists("SecurityApp/static/files/"+filename):
            os.remove("SecurityApp/static/files/"+filename)
        with open("SecurityApp/static/files/"+filename, "wb") as file:
            file.write(image_data)
        file.close()
        dd = str(date.today())
        cover_image = hideMessage("SecurityApp/static/files/"+filename, message)
        os.remove("SecurityApp/static/files/"+filename)
        cover_image.save("SecurityApp/static/files/"+filename)
        with open("SecurityApp/static/files/"+filename, "rb") as file:
            encrypted_data = file.read()
        file.close()
        hashcode = hashlib.sha256(encrypted_data).hexdigest()
        db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'cybersecurity',charset='utf8')
        db_cursor = db_connection.cursor()
        student_sql_query = "INSERT INTO files VALUES('"+username+"','"+filename+"','"+hashcode+"','"+dd+"','Steganography')"
        db_cursor.execute(student_sql_query)
        db_connection.commit()
        context= {'data':'<font size="3" color="blue">Message successfully hidden in given image</font>'}
        return render(request, 'ImageSteg.html', context)

def Download(request):
    if request.method == 'GET':
        global fileList
        name = request.GET.get('requester', False)
        with open("SecurityApp/static/files/"+name, "rb") as file:
            data = file.read()
        file.close()   
        private_key, public_key = getECCKeys()
        decrypted_data = ECCDecrypt(data, private_key)        
        private_key = generateKeys()
        decrypted_data = decryptAES(decrypted_data, private_key)
        response = HttpResponse(decrypted_data,content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename='+name
        return response              

def AccessData(request):
    if request.method == 'GET':
        global username
        output = '<table border=1 align=center width=100%><tr><th><font size="3" color="black">File Owner Name</th><th><font size="3" color="black">Filename</th>'
        output+='<th><font size="3" color="black">Hashcode</th><th><font size="3" color="black">Upload Date</th><th><font size="3" color="black">File Security Type</th>'
        output+='<th><font size="3" color="black">Steg Image</th><th><font size="3" color="black">Download File</th></tr>'
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'cybersecurity',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select * FROM files where username='"+username+"'")
            rows = cur.fetchall()
            for row in rows:
                name = row[0]
                fname = row[1]
                hashcode = row[2]
                upload_date = row[3]
                upload_type = row[4]
                output += '<tr><td><font size="3" color="black">'+str(name)+'</td><td><font size="3" color="black">'+str(fname)+'</td>'
                output+='<td><font size="3" color="black">'+hashcode+'</td>'
                output+='<td><font size="3" color="black">'+upload_date+'</td>'
                output+='<td><font size="3" color="black">'+upload_type+'</td>'
                if upload_type == "Steganography":
                    output+='<td><img src="static/files/'+fname+'" height="200" width="200"/></td>'
                    message = extractMessage("SecurityApp/static/files/"+fname)
                    output+='<td><font size="3" color="blue">Hidden Message = '+message+'</td>'
                else:
                    output+='<td><font size="3" color="red">--</td>'
                    output +='<td><a href=\'Download?requester='+fname+'\'><font size=3 color=red>Download</font></a></td></tr>'
        output += "</table><br/><br/><br/><br/>"    
        context= {'data':output}
        return render(request, 'UserScreen.html', context)     

def ImageSteg(request):
    if request.method == 'GET':
        return render(request, 'ImageSteg.html', {})

def HybridEncryptionAction(request):
    if request.method == 'POST':
        global username       
        myfile = request.FILES['t1'].read()
        fname = request.FILES['t1'].name
        dd = str(date.today())
        #get IBE key for file encryption
        private_key = generateKeys()
        encrypted_data = encryptAES(myfile, private_key)
        private_key, public_key = getECCKeys()
        encrypted_data = ECCEncrypt(encrypted_data, public_key)
        with open("SecurityApp/static/files/"+fname, "wb") as file:
            file.write(encrypted_data)
        file.close()
        hashcode = hashlib.sha256(encrypted_data).hexdigest()
        db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'cybersecurity',charset='utf8')
        db_cursor = db_connection.cursor()
        student_sql_query = "INSERT INTO files VALUES('"+username+"','"+fname+"','"+hashcode+"','"+dd+"','Hybrid Encryption')"
        db_cursor.execute(student_sql_query)
        db_connection.commit()
        context= {'data':'<font size="3" color="blue">Hybrid Encrypted file successfully saved at server network</font>'}
        return render(request, 'HybridEncryption.html', context)

def HybridEncryption(request):
    if request.method == 'GET':
        return render(request, 'HybridEncryption.html', {})

def UserLogin(request):
    if request.method == 'GET':
        return render(request, 'UserLogin.html', {})

def index(request):
    if request.method == 'GET':
        return render(request, 'index.html', {})

def Register(request):
    if request.method == 'GET':
       return render(request, 'Register.html', {})

def RegisterAction(request):
    if request.method == 'POST':
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        status = "none"
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'cybersecurity',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select username FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username:
                    status = '<font size="3" color="blue">Username already exists</font>'
                    break
        if status == "none":
            db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'cybersecurity',charset='utf8')
            db_cursor = db_connection.cursor()
            student_sql_query = "INSERT INTO register VALUES('"+username+"','"+password+"','"+contact+"','"+email+"','"+address+"')"
            db_cursor.execute(student_sql_query)
            db_connection.commit()
            print(db_cursor.rowcount, "Record Inserted")
            if db_cursor.rowcount == 1:
                status = '<font size="3" color="blue">Signup process completed</font>'
        context= {'data': status}
        return render(request, 'Register.html', context)

def sendOTP(email, otp_value):
    em = []
    em.append(email)
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as connection:
        email_address = 'kaleem202120@gmail.com'
        email_password = 'xyljzncebdxcubjq'
        connection.login(email_address, email_password)
        connection.sendmail(from_addr="kaleem202120@gmail.com", to_addrs=em, msg="Subject : Your OTP : "+otp_value)    

def UserLoginAction(request):
    if request.method == 'POST':
        global username, otp, email
        uname = request.POST.get('username', False)
        password = request.POST.get('password', False)
        index = 0
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'cybersecurity',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select username, password, email FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == uname and password == row[1]:
                    email = row[2]
                    username = uname
                    index = 1
                    break		
        if index == 1:
            otp = str(random.randint(1000, 9999))
            sendOTP(email, otp)
            context= {'data':'<font size="3" color="blue">OTP sent to your mail</font>'}
            return render(request, 'OTP.html', context)
        else:
            context= {'data':'<font size="3" color="blue">login failed</font>'}
            return render(request, 'UserLogin.html', context)

def OTPAction(request):
    if request.method == 'POST':
        global username, otp
        user_otp = request.POST.get('t1', False)
        if otp == user_otp:
            context= {'data':'<font size="3" color="blue">OTP Succesfully Validated<br/>welcome '+username+'</font>'}
            return render(request, 'UserScreen.html', context)
        else:
            context= {'data':'<font size="3" color="blue">login failed</font>'}
            return render(request, 'OTP.html', context)         

