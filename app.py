#!/usr/bin/env python3
"""
Magi REST API © MIT licensed
https://magi.duinocoin.com | https://m-core.org
https://github.com/revoxhere/magi-rest-api
Duino-Coin Team & Community 2019-2021
"""

import gevent.monkey
gevent.monkey.patch_all()

import sys
import os
from flask_cors import CORS
from flask_caching import Cache
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_ipban import IpBan
from bcrypt import hashpw, gensalt, checkpw
import threading
from datetime import datetime
import requests
from re import sub, match
from time import sleep, time
from sqlite3 import connect as sqlconn
from json import load
import traceback
from magilib import *
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import ssl
from dotenv import load_dotenv


load_dotenv()
CAPTCHA_SECRET_KEY = os.getenv('CAPTCHA_KEY') 
MAGI_PASS = os.getenv('MAGI_PASS') 
DUCO_EMAIL = os.getenv('MAGI_MAIL')
magi_rpc_user = os.getenv('MAGI_RPC_USER') 
magi_rpc_pass = os.getenv('MAGI_RPC_PASS')
DATABASE = 'magi-db.db'
BCRYPT_ROUNDS = 6
DB_TIMEOUT = 3
SAVE_TIME = 15

config = {
    "DEBUG": False,
    "CACHE_TYPE": "redis",
    "CACHE_REDIS_URL": "redis://localhost:6379/0",
    "CACHE_DEFAULT_TIMEOUT": SAVE_TIME,
    "JSONIFY_PRETTYPRINT_REGULAR": False}


def forwarded_ip_check():
    return request.environ.get('HTTP_X_REAL_IP', request.remote_addr)


app = Flask(__name__)
app.config.from_mapping(config)
cache = Cache(app)
CORS(app)

limiter = Limiter(
    key_func=forwarded_ip_check,
    default_limits=["5000 per day", "1 per 1 second"])
limiter.init_app(app)

ip_ban = IpBan(ban_seconds=60*60, ban_count=10,
               persist=True, record_dir="config/ipbans/",
               ipc=True, secret_key=MAGI_PASS)
ip_ban.init_app(app)

overrides = [MAGI_PASS]
banlist = []
magi = rvxMagi(magi_rpc_user, magi_rpc_pass)
print(magi.get_balance(), "XMG total")

with open('register_email.html', 'r') as file:
    html = file.read()

def _success(result, code=200):
    return jsonify(success=True, result=result), code


def _error(string, code=200):
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    ip_ban.add(ip=ip_addr)

    dbg("Error", string, ip_addr)
    return jsonify(success=False, message=string), code


def dbg(*message):
    print(*message)


def send_registration_email(username, email):
    message = MIMEMultipart("alternative")
    message["Subject"] = (u"\U0001F44B" +
                          " Welcome on the Coin Magi network, "
                          + str(username)
                          + "!")
    try:
        message["From"] = DUCO_EMAIL
        message["To"] = email

        email_body = html.replace("{user}", str(username))
        part = MIMEText(email_body, "html")
        message.attach(part)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
            smtp.login(
                DUCO_EMAIL, MAGI_PASS)
            smtp.sendmail(
                DUCO_EMAIL, email, message.as_string())
            return True
    except Exception as e:
        print(traceback.format_exc())
        return False


@app.route("/balances/<username>")
@limiter.limit("30 per minute")
@cache.cached(timeout=SAVE_TIME)
def get_account_data(username):
    global magi
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    dbg("/GET/balances/"+str(username), ip_addr)
    try:
        while true:
            try:
                return _success(magi.account_data(username))
            except Exception as e:
                magi = rvxMagi(magi_rpc_user, magi_rpc_pass)
    except Exception as e:
        return _error(f"This user doesn't exist: {e}")


@app.route("/users/<username>")
@limiter.limit("30 per minute")
@cache.cached(timeout=SAVE_TIME)
def get_user_data(username):
    global magi
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        limit = int(request.args.get('limit', 10))
    except Exception as e:
        return _error(f"Incorrect data: {e}")

    dbg("/GET/users/"+str(username), ip_addr)

    try:
        while True:
            try:
                return _success(magi.user_data(username, limit))
            except Exception as e:
                magi = rvxMagi(magi_rpc_user, magi_rpc_pass)
    except Exception as e:
        return _error(f"This user doesn't exist: {e}")


@app.route("/user_transactions/<username>")
@cache.cached(timeout=SAVE_TIME)
def get_transaction_for_user(username: str):
    global magi
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        limit = int(request.args.get('limit', 10))
    except Exception as e:
        return _error(f"Incorrect data: {e}")

    dbg("/GET/user_transactions/"+str(username), ip_addr)

    try:
        while True:
            try:
                transactions = magi.get_transactions(username, limit)
            except Exception as e:
                if str(e) != "Request-sent":
                    raise
                else:
                    magi = rvxMagi(magi_rpc_user, magi_rpc_pass)

        transactions_prep = []
        for transaction in transactions:
            transactions_prep.append(magi.transaction_data(transaction))

        return _success(transactions_prep)
    except Exception as e:
        return _error(f"No transactions found: {e}")


@app.route("/transactions/<txid>")
@cache.cached(timeout=SAVE_TIME)
def get_transaction_by_txid(txid: str):
    global magi
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    dbg("/GET/transactions/"+str(txid), ip_addr)

    try:
        while True:
            try:
                transaction = magi.transaction_by_txid(txid)
                return _success(transaction)
            except Exception as e:
                if str(e) != "Request-sent":
                    print(traceback.format_exc())
                    raise
                else:
                    magi = rvxMagi(magi_rpc_user, magi_rpc_pass)
    except Exception as e:
        return _error(f"No transactions found: {e}")


@app.route("/statistics")
@cache.cached(timeout=SAVE_TIME)
def get_stats():
    global magi
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    dbg("/GET/statistics", ip_addr)

    try:
        while True:
            try:
                return _success(magi.statistics())
            except Exception as e:
                if str(e) != "Request-sent":
                    raise
                else:
                    magi = rvxMagi(magi_rpc_user, magi_rpc_pass)
    except Exception as e:
        return _error(f"Error fetching stats: {e}")


@app.route("/all_balances")
@cache.cached(timeout=SAVE_TIME)
def all_balances():
    global magi
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    dbg("/GET/all_balances", ip_addr)

    try:
        to_return = {}
        for wallet in magi.get_wallets():
            if (wallet["account"]
                and not wallet["account"] in to_return
                    and wallet["amount"] != 0):
                to_return[str(wallet["account"])] = magi.account_data(
                    wallet["account"])

        return _success(to_return)
    except Exception as e:
        return _error(f"Error fetching stats: {e}")


@app.route("/transaction/")
@limiter.limit("2 per minute")
def api_transaction():
    global magi
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        username = request.args.get('username', None)
        unhashed_pass = request.args.get('password', None)
        recipient = request.args.get('recipient', None)
        amount = float(request.args.get('amount', None))
        memo = request.args.get('memo', None)[0:50]
        memo = sub(r'[^A-Za-z0-9 .()-:/!#_+-]+', ' ', str(memo))
        if len(recipient) != 34:
            try:
                while True:
                    try:
                        recipient = magi.get_account_address(recipient)
                        break
                    except Exception as e:
                        if str(e) != "Request-sent":
                            raise
                        else:
                            magi = rvxMagi(magi_rpc_user, magi_rpc_pass)
            except:
                return _error("NO,Recipient doesnt exist")
    except Exception as e:
        return _error(f"NO,Incorrect data: {e}")

    dbg("/GET/transaction", username, amount, recipient, memo, ip_addr)

    if not memo or memo == "-" or memo == "":
        memo = "none"

    if round(amount, 5) <= 0:
        return _error("NO,Incorrect amount")

    if not unhashed_pass in overrides:
        login_protocol = login(username, unhashed_pass.encode('utf-8'))
        if not login_protocol[0]:
            return _error(login_protocol[1])

    try:
        if str(recipient) == str(username):
            return _error("NO,You\'re sending funds to yourself")

        if str(amount) == "" or float(amount) <= 0:
            return _error("NO,Incorrect amount")

        while True:
            try:
                balance = magi.get_balance(username)
                if float(balance) < float(amount):
                    return _error("NO,Incorrect amount")
                break
            except Exception as e:
                magi = rvxMagi(magi_rpc_user, magi_rpc_pass)

        if float(balance) >= float(amount):
            while True:
                try:
                    global_last_block_hash_cp = magi.send(
                        username, recipient, amount, memo)
                    break
                except Exception as e:
                    if str(e) != "Request-sent":
                        raise
                    else:
                        magi = rvxMagi(magi_rpc_user, magi_rpc_pass)

            dbg("Successfully transferred", amount, "from",
                username, "to", recipient, global_last_block_hash_cp)

            return _success("OK,Successfully transferred funds,"
                            + str(global_last_block_hash_cp))
    except Exception as e:
        print(traceback.format_exc())
        return _error(f"NO,Internal server error: {e}")


def login(username: str, unhashed_pass: str):
    if not match(r"^[A-Za-z0-9_-]*$", username):
        return (False, "Incorrect username")

    try:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                    FROM Users
                    WHERE username = ?""",
                (str(username),))
            data = datab.fetchone()

        if data:
            stored_password = data[1]
        else:
            return (False, "No user found")

        try:
            if checkpw(unhashed_pass, stored_password):
                return (True, "Correct password")
            return (False, "Invalid password")

        except Exception:
            if checkpw(unhashed_pass, stored_password.encode('utf-8')):
                return (True, "Correct password")
            return (False, "Invalid password")
    except Exception as e:
        return (False, "DB Err: " + str(e))


def email_exists(email: str):
    try:
        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """SELECT *
                    FROM Users
                    WHERE email = ?""",
                (str(email),))
            data = datab.fetchone()

        if data:
            return True
        return False
    except Exception as e:
        print(e)
        return True


@app.route("/auth/<username>")
@limiter.limit("6 per minute")
def api_auth(username=None):
    try:
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        unhashed_pass = request.args.get('password', None)
        if not unhashed_pass:
            raise Exception("No password specified")
        unhashed_pass = unhashed_pass.encode('utf-8')
    except Exception as e:
        return _error(f"Invalid data: {e}")

    dbg("/GET/auth", username)

    if unhashed_pass.decode() in overrides:
        return _success("Correct password")

    if username in banlist:
        ip_addr_ban(ip_addr)
        return _error("User banned")

    login_protocol = login(username, unhashed_pass)
    if login_protocol[0] == True:
        return _success(login_protocol[1])
    else:
        return _error(login_protocol[1])


@app.route("/register/")
@limiter.limit("5 per hour")
def register():
    global magi
    try:
        username = str(request.args.get('username', None))
        unhashed_pass = str(request.args.get('password', None)).encode('utf-8')
        email = str(request.args.get('email', None))
        captcha = request.args.get('captcha', None)
        ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        postdata = {'secret': CAPTCHA_SECRET_KEY,
                    'response': captcha}
    except Exception as e:
        return _error(f"Invalid data: {e}")

    if len(username) > 64 or len(unhashed_pass) > 128 or len(email) > 64:
        return _error("Submited data is too long")

    if not match(r"^[A-Za-z0-9_-]*$", username):
        return _error("You have used unallowed characters in the username")

    if not "@" in email or not "." in email:
        return _error("You have provided an invalid e-mail address")

    if email_exists(email):
        return _error("This e-mail was already used")

    try:
        captcha_data = requests.post(
            'https://hcaptcha.com/siteverify', data=postdata).json()
        if not captcha_data["success"]:
            return _error("Incorrect captcha")
    except Exception as e:
        return _error("Captcha error: "+str(e))

    while True:
        try:
            if magi.wallet_exists(username):
                return _error("This username is already registered")
            break
        except Exception as e:
            if str(e) != "Request-sent":
                raise
            else:
                magi = rvxMagi(magi_rpc_user, magi_rpc_pass)

    try:
        password = hashpw(unhashed_pass, gensalt(rounds=BCRYPT_ROUNDS))
    except Exception as e:
        return _error("Bcrypt error: " +
                      str(e) + ", plase try using a different password")

    try:
        threading.Thread(
            target=send_registration_email,
            args=[username, email]).start()
        created = str(datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

        with sqlconn(DATABASE, timeout=DB_TIMEOUT) as conn:
            datab = conn.cursor()
            datab.execute(
                """INSERT INTO Users
                (username, password, email, balance, created, tbd)
                VALUES(?, ?, ?, ?, ?, ?)""",
                (username, password, email, 0.0, created, ""))
            conn.commit()

        while True:
            try:
                acc = magi.create_wallet(username)
                break
            except Exception as e:
                if str(e) != "Request-sent":
                    raise
                else:
                    magi = rvxMagi(magi_rpc_user, magi_rpc_pass)
        result = {
            "address": acc[0],
            "account": acc[1]}

        dbg(f"Success: registered {username} ({email})")
        return _success(result)
    except Exception as e:
        return _error(f"Error registering new account: {e}")
