import os
import base64

#from datetime import datetime
from sqlalchemy import Column, Integer, String
from database import Base, db_session
#import settings

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password = Column(String(50))
    first_name = Column(String(50))
    last_name = Column(String(50))
    #  ---------------------------------------------------------------------------------
    #  Contact details backing the "Profile Management" feature (feature 5).
    #  Every seeded value below is FAKE test data, there is no real person behind it.
    #  RASP-VULN-005 exposes these on the device only, never on this side.
    #  ---------------------------------------------------------------------------------
    email = Column(String(120))
    phone = Column(String(40))
    address = Column(String(200))
    # ---------------------------------------------------------------------------------

    def __init__(self, username=None, password=None, first_name=None, last_name=None,
                 email=None, phone=None, address=None):
        self.username = username
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.address = address

    def __repr__(self):
        return '<User %r>' % (self.username)

    @property
    def values(self):
        return {"username" : self.username,
                "first_name" : self.first_name,
                "last_name" : self.last_name,
                }


class Account(Base):
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True) 
    account_number = Column(Integer, unique=True)
    type = Column(String(50))
    balance = Column(Integer)
    user_id = Column(Integer)
    user = Column(String(50))

    def __init__(self, account_number=None, type=type, balance=None, user=None):
        self.account_number = account_number
        self.type = type
        self.balance = balance
        self.user = user

    def __repr__(self):
        return '<Account %r>' % (self.account_number)  


    @property
    def values(self):
        return {"account_number" : self.account_number,
                "type" : self.type,
                "balance" : self.balance,
                }    


'''
Every money movement of the six new features is written to this table so that
"Transaction History" (feature 2) has a server side source of truth.

    type          TRANSFER | DEPOSIT | BILL_PAYMENT
    direction     DEBIT | CREDIT
    amount        integer, always positive
    counterparty  the other account number / beneficiary name / biller
'''
class Transaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True)
    user = Column(String(50), index=True)
    account_number = Column(String(20))
    type = Column(String(30))
    direction = Column(String(10))
    amount = Column(Integer)
    counterparty = Column(String(80))
    reference = Column(String(40))
    txn_date = Column(String(40))

    def __init__(self, user=None, account_number=None, type=None, direction=None,
                 amount=None, counterparty=None, reference=None, txn_date=None):
        self.user = user
        self.account_number = account_number
        self.type = type
        self.direction = direction
        self.amount = amount
        self.counterparty = counterparty
        self.reference = reference
        self.txn_date = txn_date

    def __repr__(self):
        return '<Transaction %r>' % (self.id)

    @property
    def values(self):
        return {"id": self.id,
                "account_number": self.account_number,
                "type": self.type,
                "direction": self.direction,
                "amount": self.amount,
                "counterparty": self.counterparty,
                "reference": self.reference,
                "date": self.txn_date,
                }


'''
Beneficiaries registered by the account holder (feature 3).
'''
class Beneficiary(Base):
    __tablename__ = 'beneficiaries'
    id = Column(Integer, primary_key=True)
    user = Column(String(50), index=True)
    name = Column(String(80))
    account_number = Column(String(20))
    bank_name = Column(String(80))
    account_type = Column(String(30))
    created_date = Column(String(40))

    def __init__(self, user=None, name=None, account_number=None, bank_name=None,
                 account_type=None, created_date=None):
        self.user = user
        self.name = name
        self.account_number = account_number
        self.bank_name = bank_name
        self.account_type = account_type
        self.created_date = created_date

    def __repr__(self):
        return '<Beneficiary %r>' % (self.id)

    @property
    def values(self):
        return {"id": self.id,
                "name": self.name,
                "account_number": self.account_number,
                "bank_name": self.bank_name,
                "account_type": self.account_type,
                "date": self.created_date,
                }


'''
Bill payments issued from the "Bill Payment" feature (feature 4).
'''
class BillPayment(Base):
    __tablename__ = 'bill_payments'
    id = Column(Integer, primary_key=True)
    user = Column(String(50), index=True)
    category = Column(String(50))
    bill_number = Column(String(80))
    amount = Column(String(40))
    amount_value = Column(Integer)
    payer_account = Column(String(20))
    status = Column(String(30))
    reference = Column(String(40))
    paid_date = Column(String(40))

    def __init__(self, user=None, category=None, bill_number=None, amount=None,
                 amount_value=None, payer_account=None, status=None, reference=None,
                 paid_date=None):
        self.user = user
        self.category = category
        self.bill_number = bill_number
        self.amount = amount
        self.amount_value = amount_value
        self.payer_account = payer_account
        self.status = status
        self.reference = reference
        self.paid_date = paid_date

    def __repr__(self):
        return '<BillPayment %r>' % (self.id)

    @property
    def values(self):
        return {"id": self.id,
                "category": self.category,
                "bill_number": self.bill_number,
                "amount": self.amount,
                "payer_account": self.payer_account,
                "status": self.status,
                "reference": self.reference,
                "date": self.paid_date,
                }
