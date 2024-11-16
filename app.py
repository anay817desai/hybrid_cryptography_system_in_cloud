import os
import  re
import time
import base64
import smtplib
import sqlite3 
import warnings
import datetime
import numpy as np
import pandas as pd
from utils import *
from email.message import Message
from Cryptodome.Cipher import AES 
from datetime import timedelta, date
from email.mime.text import MIMEText
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.RFC1751 import key_to_english, english_to_key
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from flask import Flask, request, render_template, redirect, url_for, session, flash
warnings.filterwarnings("ignore", category=UserWarning)
#======================================================================================

application = Flask(__name__)
app=application

app.secret_key = 'your secret key'


#======================================================================================

#database connection (sqlite)
#create sqlite database file
if os.path.exists('hybrid_cryptography_system.db'):
    pass
else:
    create_db_table()


mydb = sqlite3.connect("hybrid_cryptography_system.db", check_same_thread=False)
mydb.row_factory = sqlite3.Row
mycursor = mydb.cursor()
#======================================================================================


#flask code
@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'pass' in request.form:
        username = request.form['username']
        password = request.form['pass']
        sql="SELECT * FROM User_Master WHERE username = ? AND password = ?"
        mycursor.execute(sql,(username, password, ))
        userdata = mycursor.fetchone()
        if userdata:
            session['loggedin'] = True
            session['u_id'] = userdata['u_id']
            session['username'] = userdata['username']
            msg = session['username']
            return redirect(url_for('index'))
            return render_template('index.html', msg = msg)
        else:
            msg = 'Incorrect username / password !'
        
    return render_template('login.html', msg = msg)


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('u_id', None)
    session.pop('username', None)
    return redirect(url_for('signin'))


@app.route('/signup')
def signup():
    return redirect(url_for('register'))


@app.route('/signin')
def signin():
    return redirect(url_for('login'))


@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'pass' in request.form and 'emailid' in request.form and 'fullname' in request.form and 'mobileno' in request.form :
        username = request.form['username']
        password = request.form['pass']
        emailid = request.form['emailid']
        fullname = request.form['fullname']
        mobileno = request.form['mobileno']
        myquery="SELECT * FROM User_Master WHERE username = ?"
        mycursor.execute(myquery, (username, ))
        userdata = mycursor.fetchone()
        if userdata:
            msg = 'User already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', emailid):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not emailid or not fullname or not mobileno:
            msg = 'Please fill out the details properly !'
        else:
            sql="INSERT INTO User_Master VALUES (NULL, ?, ?, ?, ?, ?)"
            mycursor.execute(sql, (username, fullname, mobileno, emailid, password, ))
            mydb.commit()
            msg = 'You have Successfully Registered !'

    elif request.method == 'POST':
        msg = 'Please fill out the details !'
    return render_template('registration.html', msg = msg)


@app.route('/index', methods =['GET'])
def index(): 
    if 'username' not in session.keys():
        return redirect(url_for('login'))
    else:
        msg = session['username']
        return render_template('index.html', msg = msg)


@app.route('/adddatapage', methods =['GET', 'POST'])
def adddatapage():
    if 'username' not in session.keys():
        return redirect(url_for('login'))
    else:
        msg = session['username']
        
        return render_template('adddata.html', msg = msg)


@app.route('/addhealthdata', methods =['POST'])
def addhealthdata():

    if 'username' not in session.keys():
        return redirect(url_for('login'))
    else:
        try:
            msg = session['username']
            user_id = session['u_id']
            age = str(request.form['age'])
            trestbps = str(request.form['trestbps'])
            cholestoral = str(request.form['cholestoral'])
            thalach = str(request.form['thalach'])
            curr_date_time = currdatetime()
            encstart = time.time()  #enc time
            org_key = get_random_bytes(16)
            #encryption
            ciphertext_age, key = aeschachaencryption(org_key, age)
            ciphertext_trestbps, key = aeschachaencryption(org_key, trestbps)
            ciphertext_cholestoral, key = aeschachaencryption(org_key, cholestoral)
            ciphertext_thalach, key = aeschachaencryption(org_key, thalach)
            #insert enc data
            sql="INSERT INTO Health_Data VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            mycursor.execute(sql, (user_id, curr_date_time, ciphertext_age, ciphertext_trestbps, ciphertext_cholestoral, ciphertext_thalach, key, age, trestbps, cholestoral, thalach,))
            mydb.commit()
            successmsg = "Data Added Successfully"
            encend = time.time()
            
            sql="SELECT emailid FROM User_Master WHERE u_id = ?"
            mycursor.execute(sql,(user_id,))
            email_database = mycursor.fetchone()
            email_id = email_database['emailid']
            subject = "Encryption/Decryption Key of Health Data"
            textmsg = "Your Data Added Successfully - Datetime: {} & Key: {}".format(curr_date_time,key)
            send_email(textmsg,subject,email_id)
            
            enctotalt = encend - encstart 
            enctotalt = enctotalt * 1000
            encrypt_time = "Encryption Time: {} ms".format(int(enctotalt))
            return render_template('adddata.html', msg = msg, successmsg = successmsg, encrypt_time=encrypt_time)

        except:
            successmssg="Sorry Please Enter Correct Format Value or There is Some Technical Issue to Encrypt Data...!!!"
            return render_template('adddata.html', msg = msg, successmsg = successmsg)


@app.route('/viewencryptdata', methods =['GET'])
def viewencryptdata(): 
    if 'username' not in session.keys():
        return redirect(url_for('login'))
    else:
        msg = session['username']
        user_id = session['u_id']
        #sql query
        sql="Select ROW_NUMBER() OVER (ORDER BY hd_id desc) AS serial_no, hd_id, datetime, age_enc, trestbps_enc, cholestoral_enc, thalach_enc from Health_Data Where u_id = ?"
        mycursor.execute(sql, (user_id,))
        encrypteddata = mycursor.fetchall()

        return render_template('viewencryptdata.html',msg = msg, encrypteddata=encrypteddata)


@app.route('/decryptdata', methods =['POST'])
def decryptdata(): 
    if 'username' not in session.keys():
        return redirect(url_for('login'))
    else:
        msg = session['username']
        hdid = request.form['hdid']
        if hdid is not None:
            return render_template('viewdecryptdata.html',msg = msg, hd_id=hdid, outputvalues='nonoutput')
        else:
            redirect(url_for('viewencryptdata'))


@app.route('/viewhealthdata', methods=['POST'])
def viewhealthdata():
    if 'username' not in session.keys():
        return redirect(url_for('login'))
    else:
        msg = session['username']
        user_id = session['u_id']
        if 'hdidv' in request.form:
            try:
                decstart = time.time()
                hdidv = request.form['hdidv']
                engkey = request.form['decryptkey']
                #sql query
                sql="Select * from Health_Data Where hd_id = ?"
                mycursor.execute(sql, (hdidv,))
                viewencdata = mycursor.fetchone()
                age_enc = viewencdata['age_enc']
                trestbps_enc = viewencdata['trestbps_enc']
                cholestoral_enc = viewencdata['cholestoral_enc']
                thalach_enc = viewencdata['thalach_enc']
                #decryption
                age = aeschachadecryption(age_enc, engkey)
                trestbps = aeschachadecryption(trestbps_enc, engkey)
                cholestoral = aeschachadecryption(cholestoral_enc, engkey)
                thalach = aeschachadecryption(thalach_enc, engkey)
                decryptdata_dict = dict({'age':age, 'trestbps':trestbps, 'cholestoral':cholestoral, 'thalach':thalach})
                successmssg="Data Decrypted Successfully"
                if 60 <= int(thalach) <= 100:
                    predmssg = "Heart Condition Normal"
                else:
                    predmssg = "Heart Condition Abnormal"
                
                decend = time.time()
                dectotalt = decend - decstart
                dectotalt = dectotalt * 1000
                decrypt_time = "Decryption Time: {} ms".format(int(dectotalt))
                return render_template('viewdecryptdata.html', msg = msg,successmssg=successmssg, decryptdata_dict=decryptdata_dict, predmssg=predmssg, decrypt_time=decrypt_time)
            
            except:
                successmssg="Sorry Key is Incorrect or There is Some Technical Issue...!!!"
                return render_template('viewdecryptdata.html',msg = msg, hd_id=hdidv, outputvalues='nonoutput', successmssg=successmssg)




if __name__ == '__main__':
    # Run the application
    app.run(host='0.0.0.0', port=5000)



