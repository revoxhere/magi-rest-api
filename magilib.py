#!/usr/bin/env python3
"""
Magi RPC API © MIT licensed
https://magi.duinocoin.com | https://m-core.org
https://github.com/revoxhere/magi-rest-api
Duino-Coin Team & Community 2019-2021
"""

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from requests import get
from time import time
from hashlib import sha1
from random import randint
from datetime import datetime


class rvxMagi():
    def __init__(self, rpc_user, rpc_password, ip="127.0.0.1:8232"):
        """
        Connects to a Magi wallet
        """
        self.coingecko = get("https://api.coingecko.com/api/v3/simple/"
                             + "price?ids=bitcoin&vs_currencies=usd").json()
        self.btcpop = get("https://btcpop.co/api/market-public.php").json()
        self.total_blocks = int(get(
            "https://chainz.cryptoid.info/xmg/api.dws?q=getblockcount").text)
        self.ducoexchange = get(
            "https://exchange.duinocoin.com/api/v1/rates").json()
        self.duco_api = get(
            "https://raw.githubusercontent.com/revoxhere/duco-statistics/master/api.json").json()

        self.blocks = 1
        self.new_time = time()

        self.magi = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{ip}")

    def get_wallets(self):
        """
        Gets a list of all wallets
        """
        return self.magi.listreceivedbyaddress(0, True)

    def get_account_name(self, address):
        """
        Returns account name associated with address
        """
        if len(address) == 34:
            return self.magi.getaccount(address)
        else:
            return address

    def get_account_address(self, address):
        if len(address) != 34:
            return self.magi.getaddressesbyaccount(address)[0]
        else:
            return address

    def get_transactions(self, address_id, limit=10):
        """
        Gets transaction list of address name
        """
        if not address_id:
            txs = []
        elif address_id == True:
            txs = self.magi.listtransactions()
        else:
            if len(address_id) == 34:
                address_id = rvxMagi.get_account_name(self, address_id)
            txs = self.magi.listtransactions(address_id, limit)
        return txs

    def create_wallet(self, name=None):
        """
        Creates a new wallet
        """
        if rvxMagi.wallet_exists(self, name):
            raise Exception("Address already taken")

        if not name:
            name = sha1(
                str(randint(-999999, 999999)).encode()
            ).hexdigest()[:8]

        address = self.magi.getnewaddress(name)

        return address, name

    def send(self, sender, recipient, amount, memo="none", txfee=0.005, subtract_fee=True):
        """
        Sends funds to address
        """
        if len(sender) == 34:
            sender = rvxMagi.get_account_name(self, sender)

        if amount <= txfee:
            raise Exception("Amount too small")

        if subtract_fee:
            amount = amount - txfee

        self.magi.settxfee(txfee)

        txid = self.magi.sendfrom(str(sender), str(
            recipient), float(amount), 1, str(memo))

        return txid

    def get_price(self):
        def _get_btcpop_price():
            for row in self.btcpop:
                if row["ticker"] == "XMG":
                    return float(row["lastTradePrice"]) * float(self.coingecko["bitcoin"]["usd"])

        def _get_ducoexchange_price():
            return self.ducoexchange["result"]["xmg"]["buy"] * self.duco_api["Duco price"]

        def _get_moondex_price():
            """
            Api is broken at the time of writing this lib (hopefully temporarily)
            so this returns zero for now
            https://moon.moondex.org/api/v1/public/getmarketsummary?market=BTC-XMG
            """
            return 0

        prices = {
            "btcpop": round(_get_btcpop_price(), 8),
            "ducoexchange": round(_get_ducoexchange_price(), 8),
            "moondex": round(_get_moondex_price(), 8)
        }
        prices["max"] = prices[max(prices, key=prices.get)]

        return prices

    def statistics(self):
        """
        Returns networks stats
        """
        info = self.magi.getmininginfo()
        diff = info["difficulty"]

        res = {
            "difficulty": {
                "pow": float(diff["proof-of-work"]),
                "pos": float(diff["proof-of-stake"])
            },
            "blocktx": int(info["currentblocktx"]),
            "blocks": int(info["blocks"]),
            "reward": float(info["blockvalue"]["blockvalue"]),
            "hashrate": float(info["networkhashps"]),
            "price": rvxMagi.get_price(self)
        }

        return res

    def get_balance(self, account=None):
        """
        Returns balance of an account
        or total wallet balance if no address supplied
        """
        if not account:
            bal = self.magi.getbalance()
        else:
            if len(account) == 34:
                account = rvxMagi.get_account_name(self, account)
            bal = self.magi.getbalance(account, 1)

        return round(bal, 8)

    def sync_status(self):
        """
        Shows estimated time remaining for wallet to be synced
        with the network
        """
        self.old_blocks = self.blocks
        self.old_time = self.new_time
        self.blocks = self.magi.getblockcount()
        self.new_time = time()
        persec = (self.blocks-self.old_blocks) / (self.new_time-self.old_time)

        if round((self.blocks / self.total_blocks) * 100, 3) < 100:
            will_take = (self.total_blocks - self.blocks) / persec

            print(f"{round((self.blocks / self.total_blocks) * 100, 3)}% "
                  + f"({self.blocks} of {self.total_blocks}) synced "
                  + f"({self.blocks-self.old_blocks} blocks in "
                  + f"{round(self.new_time-self.old_time, 2)}s)")

            print(f"{round(persec)} blocks/sec "
                  + f"- about {round(will_take)}s "
                  + f"({round(will_take/60)}m) "
                  + f"({round(will_take/60/60)}h) remaining")

            return (False, self.total_blocks - self.blocks, self.total_blocks)
        else:
            print(f"Wallet in sync (100% of {self.total_blocks} synced)")

        return 0, self.total_blocks

    def transaction_by_txid(self, txid):
        transaction = self.magi.gettransaction(txid)

        if not "comment" in transaction:
            transaction["comment"] = "none"

        if not "fee" in transaction:
            transaction["fee"] = "unknown"
        else:
            transaction["fee"] = abs(float(transaction["fee"]))

        if "details" in transaction:
            """
            Local transaction
            """
            amount = abs(float(transaction["details"][-1]["amount"]))

            sender = transaction["details"][0]["account"]
            if sender:
                sender += f' ({transaction["details"][0]["address"]})'

            recipient = transaction["details"][-1]["account"]
            if sender:
                recipient += f' ({transaction["details"][-1]["address"]})'
            if sender == recipient:
                sender = "unknown"

        else:
            """
            Network transaction
            """
            try:
                amount = float(transaction["vout"][0]["value"])
                recipient = transaction["vout"][-1]["scriptPubKey"]["addresses"][0]
            except:
                amount = "unknown"
                recipient = "unknown"
            sender = "unknown"

        if "blockhash" in transaction:
            block = transaction["blockhash"]
        else:
            block = "unconfirmed"

        if "time" in transaction:
            timestamp = str(datetime.fromtimestamp(transaction["time"]))
        else:
            timestamp = "unknown"

        return {
            'datetime': timestamp,
            'recipient': recipient,
            'amount': amount,
            'hash': transaction["txid"],
            'memo': transaction["comment"],
            'fee': transaction["fee"],
            'sender': sender,
            'confirmations': transaction["confirmations"],
            'block': block,
            'currency': "XMG",
        }

    def wallet_exists(self, address):
        for acc in rvxMagi.get_wallets(self):
            if acc["address"] == address or acc["account"] == address:
                return True
        else:
            return False

    def transaction_data(self, transaction):
        if not "comment" in transaction:
            transaction["comment"] = "none"

        if not "fee" in transaction:
            transaction["fee"] = 0
        else:
            transaction["fee"] = abs(float(transaction["fee"]))

        if transaction["amount"] < 0:
            amount = abs(float(transaction["amount"]))
            sender = transaction["account"]
            acc_local = rvxMagi.get_account_name(self, transaction["address"])
            if acc_local:
                recipient = acc_local
            else:
                recipient = transaction["address"]
        else:
            amount = float(transaction["amount"])
            acc_local = rvxMagi.get_account_name(self, transaction["address"])
            sender = None
            recipient = transaction["account"]

        return {
            'datetime': str(datetime.fromtimestamp(transaction["time"])),
            'recipient': recipient,
            'amount': amount,
            'hash': transaction["txid"],
            'memo': transaction["comment"],
            'confirmations': transaction["confirmations"],
            'fee': transaction["fee"],
            'sender': sender,
            'currency': "XMG"
        }

    def account_data(self, user):
        return {
            'username': str(rvxMagi.get_account_name(self, user)),
            'address': str(rvxMagi.get_account_address(self, user)),
            'balance': float(rvxMagi.get_balance(self, user)),
            'currency': "XMG"
        }

    def user_data(self, user, limit=10):
        transactions = rvxMagi.get_transactions(self, user, limit)
        transactions_prep = []
        for transaction in transactions:
            transactions_prep.append(
                rvxMagi.transaction_data(self, transaction))

        return {
            'price': rvxMagi.get_price(self),
            'balance': rvxMagi.account_data(self, user),
            'transactions': transactions_prep,
        }
