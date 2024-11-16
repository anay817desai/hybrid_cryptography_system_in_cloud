import os
import  re
import base64
import smtplib
import sqlite3 
import warnings
import datetime
import numpy as np
import pandas as pd
from email.message import Message
from Cryptodome.Cipher import AES 
from datetime import timedelta, date
from email.mime.text import MIMEText
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.RFC1751 import key_to_english, english_to_key
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
warnings.filterwarnings("ignore", category=UserWarning)

###=================== function =================

def create_db_table():
    con = sqlite3.connect("hybrid_cryptography_system.db")
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS User_Master (u_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, username VARCHAR(50), fullname VARCHAR(255), mobileno VARCHAR(50), emailid VARCHAR(255), password VARCHAR(100))")
    cur.execute("CREATE TABLE IF NOT EXISTS Health_Data (hd_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, u_id int(11), datetime VARCHAR(50), age_enc VARCHAR(255), trestbps_enc VARCHAR(255), cholestoral_enc VARCHAR(255), thalach_enc VARCHAR(255), enckey VARCHAR(255), age VARCHAR(255), trestbps VARCHAR(255), cholestoral VARCHAR(255), thalach VARCHAR(255))")


def currdatetime():
    now = datetime.datetime.now()
    date_time = now.strftime("%d-%m-%Y %H:%M:%S")
    return date_time



def aeschachaencryption(key, inpdata):
    #aes
    inp1 = bytes(inpdata, 'utf-8')
    iv = b'\x1f_\x7f\xb1\xb9\xb6\x0e\xe2oI5E\x82\xac:G'
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    ciphertext = cipher.encrypt(inp1)
    ciphertext = base64.b64encode(ciphertext).decode()
    key = base64.b64encode(key).decode()
    #chacha
    data = ciphertext
    data = data.encode("utf-8")
    aad = b"authenticated but unencrypted data"
    chachakey = b'.\xf6\xf5@\xbf\x85\xac)\xe5\x02\xb2\xde\xe6\x8f\x8e\x1b\xc6?\xe4\xad4|j\xe1\xc6J=\xec\xcaif\xbd'
    chacha = ChaCha20Poly1305(chachakey)
    nonce = b'|\xca\xd4\x15\x8c\x02$\xcc\xa4<\xe1\x9f'
    ct = chacha.encrypt(nonce, data, aad)
    ct = base64.b64encode(ct).decode()
    return ct, key


def aeschachadecryption(ciphertext, key):
    #chacha
    ct = base64.b64decode(ciphertext)
    chachakey = b'.\xf6\xf5@\xbf\x85\xac)\xe5\x02\xb2\xde\xe6\x8f\x8e\x1b\xc6?\xe4\xad4|j\xe1\xc6J=\xec\xcaif\xbd'
    nonce = b'|\xca\xd4\x15\x8c\x02$\xcc\xa4<\xe1\x9f'
    aad = b"authenticated but unencrypted data"
    chacha = ChaCha20Poly1305(chachakey)
    decrypt_output = chacha.decrypt(nonce, ct, aad)
    decrypt_output = decrypt_output.decode("utf-8")
    #print(decrypt_output)
    aad = b"authenticated but unencrypted data"
    #aes
    
    decodemsg = base64.b64decode(decrypt_output)
    key = base64.b64decode(key)
    iv = b'\x1f_\x7f\xb1\xb9\xb6\x0e\xe2oI5E\x82\xac:G'
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypt_data = cipher.decrypt(decodemsg)
    decrypt_data = decrypt_data.decode("utf-8")
    return decrypt_data



def send_email(textmsg,subject,emailid):
    sender = "projectmailnew2122@gmail.com"
    username = "projectmailnew2122@gmail.com"
    password = "nhoarkxyqojoieav"
    msg = MIMEText(str(textmsg))
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = emailid
    server = smtplib.SMTP("smtp.gmail.com:587")
    server.starttls()
    server.login(username, password)
    server.sendmail(sender, emailid, msg.as_string())
    server.quit()
    print("mail send successfully")



