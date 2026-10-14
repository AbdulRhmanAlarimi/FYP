#python
import getopt
import re
import sys
import random
import datetime

try:
    import web
except ImportError:  # web.py is optional, cheroot serves the Flask app directly
    web = None

from cheroot import wsgi
from flask import Flask, request
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from models import User, Account, Transaction, Beneficiary, BillPayment
from database import db_session, Base, engine
import simplejson as json

makejson = json.dumps

app = Flask(__name__)

DEFAULT_PORT_NO = 8888


def usageguide():
    print("InsecureBankv2 Backend-Server")
    print("Options:")
    print("  --port p    serve on port p (default 8888)")
    print("  --help      print this message")


@app.errorhandler(500)
def internal_servererror(error):
    print("[!]", error)
    return "Internal Server Error", 500


# ==========================================================================================
#  Schema management for the six features added for the IntelliRASP FYP research
# ==========================================================================================
#  The shipped mydb.db predates Transaction / Beneficiary / BillPayment and the users
#  table has no contact columns. Base.metadata.create_all() only creates *missing* tables,
#  it never adds a column to an existing one, so the ALTERs below do the rest. Everything
#  here is idempotent and additive: no existing table is ever dropped and no seeded row is
#  ever modified, so an already patched mydb.db keeps working.
# ==========================================================================================

BILL_CATEGORIES = [
    "Electricity",
    "Water",
    "Mobile Postpaid",
    "Broadband",
    "Insurance Premium",
    "Credit Card",
]

# ==========================================================================================
#  Signup policy - the rules enforced by /signup
# ==========================================================================================
#  Username charset/length and the password policy live here so that the endpoint stays a
#  thin wrapper around the rules and so the Android screen can mirror them. The lengths are
#  not arbitrary, they are the widths of the users table columns in models.py - a longer
#  value would be silently truncated by SQLite and the user could not log back in.
SIGNUP_USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,50}$')
SIGNUP_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
SIGNUP_MIN_PASSWORD = 6
SIGNUP_MAX_PASSWORD = 50

#  "devadmin" is answered unconditionally by /devlogin, so a row with that username would
#  be created by signup and simultaneously handed the pre-existing backdoor. It is reserved
#  here rather than silently accepted.
RESERVED_USERNAMES = ("devadmin",)

#  Every new customer starts with one "from" and one "to" account so that all six features
#  work immediately, exactly like the two seeded users.
SIGNUP_OPENING_BALANCE = 10000
SIGNUP_ACCOUNT_MIN = 100000000      # 9 digits, same shape as the seeded account numbers
SIGNUP_ACCOUNT_MAX = 999999999

#  Fake contact details. There is no real person behind any of this.
SEED_CONTACTS = {
    "dinesh": ("dinesh.test@example.invalid", "+1-555-0100",
               "12 Test Street, Sample City"),
    "jack": ("jack.test@example.invalid", "+1-555-0101",
             "34 Test Avenue, Sample City"),
}


def _add_column_if_missing(table, column, ddl_type):
    #  Engine.execute() was removed in SQLAlchemy 2.x, use a 2.x style connection.
    with engine.connect() as conn:
        existing = [r[1] for r in
                    conn.execute(text("PRAGMA table_info(%s)" % table)).fetchall()]
        if column in existing:
            return False
        conn.execute(text("ALTER TABLE %s ADD COLUMN %s %s"
                          % (table, column, ddl_type)))
        conn.commit()
    print("[schema] added %s.%s %s" % (table, column, ddl_type))
    return True


def ensure_schema():
    Base.metadata.create_all(bind=engine)

    _add_column_if_missing('users', 'email', 'VARCHAR(120)')
    _add_column_if_missing('users', 'phone', 'VARCHAR(40)')
    _add_column_if_missing('users', 'address', 'VARCHAR(200)')

    for u in User.query.all():
        if not u.email or not u.phone:
            email, phone, address = SEED_CONTACTS.get(
                u.username, ("user.test@example.invalid", "+1-555-0100", "Test Address"))
            u.email = email
            u.phone = phone
            u.address = address
    db_session.commit()


# ==========================================================================================
#  Shared helpers for the six new features
# ==========================================================================================

def authenticate():
    """Returns the User row when username+password match, otherwise None."""
    u = User.query.filter(User.username == request.form.get('username')).first()
    if not u or u.password != request.form.get('password'):
        return None
    return u


def now_stamp():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def make_reference(prefix):
    return prefix + datetime.datetime.now().strftime('%Y%m%d%H%M%S') + str(
        random.randint(100, 999))


def as_int(value):
    """Lenient parse used by every *new* endpoint. Never raises."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def account_or_none(number):
    n = as_int(number)
    if n is None:
        return None
    return Account.query.filter(Account.account_number == n).first()


# ==========================================================================================
#  Signup helpers
# ==========================================================================================

def form_field(name, label, limit):
    """A trimmed form value checked against the width of its column in models.py.

    The length check is the important half: first_name is declared VARCHAR(50) and SQLite
    does not truncate on insert, so an over-long signup value would be stored as sent and
    come back mangled, leaving a half-created customer. An over-long value is therefore
    refused rather than quietly shortened.

    @return (value, None) or (None, message).
    """
    value = (request.form.get(name) or "").strip()
    if len(value) > limit:
        return None, "%s must be at most %d characters" % (label, limit)
    return value, None


def validate_signup():
    """Checks everything the signup form submits.

    @return (cleaned dict, None) when the request is acceptable, otherwise (None, message).
    The message is the single reason the form may show back to the user.
    """
    username, problem = form_field("username", "Username", 50)
    if problem:
        return None, problem
    if not username:
        return None, "Username is required"
    if username.lower() in RESERVED_USERNAMES:
        return None, "That username is reserved"
    if not SIGNUP_USERNAME_RE.match(username):
        return None, ("Username must be 3-50 characters using letters, digits, "
                      "dot, underscore or dash")
    if User.query.filter(User.username == username).first():
        return None, "Username already exists"

    #  The password is intentionally not run through form_field(): leading and trailing
    #  spaces are significant in a password and must survive verbatim.
    password = request.form.get("password") or ""
    if not password:
        return None, "Password is required"
    if len(password) < SIGNUP_MIN_PASSWORD:
        return None, "Password must be at least %d characters" % SIGNUP_MIN_PASSWORD
    if len(password) > SIGNUP_MAX_PASSWORD:
        return None, "Password must be at most %d characters" % SIGNUP_MAX_PASSWORD
    if password.lower() == username.lower():
        return None, "Password must be different from the username"

    #  The confirmation field is compared on the client before the request is sent too, but
    #  it is verified here as well so that the endpoint is safe to call directly.
    confirm = request.form.get("confirm_password")
    if confirm is not None and confirm != password:
        return None, "Passwords do not match"

    first_name, problem = form_field("first_name", "First name", 50)
    if problem:
        return None, problem
    last_name, problem = form_field("last_name", "Last name", 50)
    if problem:
        return None, problem

    email, problem = form_field("email", "Email", 120)
    if problem:
        return None, problem
    if email and not SIGNUP_EMAIL_RE.match(email):
        return None, "Email address is not valid"

    phone, problem = form_field("phone", "Phone number", 40)
    if problem:
        return None, problem

    address, problem = form_field("address", "Address", 200)
    if problem:
        return None, problem

    return {"username": username,
            "password": password,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone": phone,
            "address": address}, None


def allocate_account_number(taken):
    """A 9 digit number that is not already used by any account.

    `taken` is a set of the numbers already in use; it is updated in place so that a pair
    of accounts for the same signup can never receive the same number.
    """
    for _ in range(500):
        number = random.randint(SIGNUP_ACCOUNT_MIN, SIGNUP_ACCOUNT_MAX)
        if number not in taken:
            taken.add(number)
            return number
    return None


# ==========================================================================================
#  Original InsecureBankv2 routes - UNCHANGED
# ==========================================================================================

'''
The function handles the authentication mechanism
'''
@app.route('/login', methods=['POST'])
def login():
    Responsemsg = "fail"
    user = request.form['username']

    # checks for presence of user in the database
    u = User.query.filter(User.username == request.form["username"]).first()

    print("u=", u)

    if u and u.password == request.form["password"]:
        Responsemsg = "Correct Credentials"
    elif u and u.password != request.form["password"]:
        Responsemsg = "Wrong Password"
    elif not u:
        Responsemsg = "User Does not Exist"
    else:
        Responsemsg = "Some Error"

    data = {"message": Responsemsg, "user": user}

    print(makejson(data))

    return makejson(data)


'''
The function responds back with the from and to debit accounts
corresponding to logged in user
'''
@app.route('/getaccounts', methods=['POST'])
def getaccounts():
    Responsemsg = "fail"
    acc1 = acc2 = from_acc = to_acc = 0

    user = request.form['username']

    # checks for presence of user in the database
    u = User.query.filter(User.username == user).first()

    if not u or u.password != request.form["password"]:
        Responsemsg = "Wrong Credentials so trx fail"
    else:
        Responsemsg = "Correct Credentials so get accounts will continue"

        a = Account.query.filter(Account.user == user)

        for i in a:
            if i.type == 'from':
                from_acc = i.account_number

        for j in a:
            if j.type == 'to':
                to_acc = j.account_number

    data = {
        "message": Responsemsg,
        "from": from_acc,
        "to": to_acc
    }

    print(makejson(data))

    return makejson(data)


'''
The function takes a new password as input and passes it on
to the change password module
'''
@app.route('/changepassword', methods=['POST'])
def changepassword():
    Responsemsg = "fail"

    newpassword = request.form['newpassword']
    user = request.form['username']

    print(newpassword)

    u = User.query.filter(User.username == user).first()

    if not u:
        Responsemsg = "Error"
    else:
        Responsemsg = "Change Password Successful"
        u.password = newpassword
        db_session.commit()

    data = {"message": Responsemsg}

    print(makejson(data))

    return makejson(data)


'''
The function handles the transaction module
'''
@app.route('/dotransfer', methods=['POST'])
def dotransfer():
    Responsemsg = "fail"

    user = request.form['username']
    amount = request.form['amount']

    u = User.query.filter(User.username == user).first()

    if not u or u.password != request.form["password"]:
        Responsemsg = "Wrong Credentials so trx fail"
    else:
        Responsemsg = "Success"

        from_acc = request.form["from_acc"]
        to_acc = request.form["to_acc"]
        amount = request.form["amount"]

        from_account = Account.query.filter(
            Account.account_number == from_acc
        ).first()

        to_account = Account.query.filter(
            Account.account_number == to_acc
        ).first()

        to_account.balance += int(request.form['amount'])
        from_account.balance -= int(request.form['amount'])

        #  Additive for the IntelliRASP FYP build: a transfer now also lands in the
        #  transaction history that feature 2 reads. The response above is unchanged.
        transfer_reference = make_reference("TX")
        db_session.add(Transaction(user=user,
                                   account_number=str(from_account.account_number),
                                   type="TRANSFER", direction="DEBIT",
                                   amount=abs(int(request.form['amount'])),
                                   counterparty=str(to_account.account_number),
                                   reference=transfer_reference,
                                   txn_date=now_stamp()))

        db_session.commit()

    data = {
        "message": Responsemsg,
        "from": from_acc,
        "to": to_acc,
        "amount": amount
    }

    return makejson(data)


'''
The function provides login mechanism to a developer user
during development phase
'''
@app.route('/devlogin', methods=['POST'])
def devlogin():
    user = request.form['username']

    Responsemsg = "Correct Credentials"

    data = {
        "message": Responsemsg,
        "user": user
    }

    print(makejson(data))

    return makejson(data)


# ==========================================================================================
#  User signup - self-service registration
# ==========================================================================================
#  This is the endpoint behind the "Create User" button on the login screen and the
#  SignUpActivity of the Android client. It replaces the Work-In-Progress stub that the
#  original InsecureBankv2 shipped in LoginActivity.createUser().
#
#  Unlike /paybill and /deposit this endpoint is fully validated, on purpose: the research
#  rule for this repository is that a vulnerability only exists where INTENTIONAL_
#  VULNERABILITIES.md says it does, and signup is not one of the six. Do not weaken the
#  checks in validate_signup() - they are the thing being demonstrated, not an oversight.
#
#  What a successful signup does:
#     1. inserts one row in `users` (no password is ever echoed back in the response)
#     2. allocates a unique 9 digit "from" account and a unique 9 digit "to" account with
#        the standard opening balance, so the new customer can use all six features
#        straight away
#
#  No authentication is possible or expected here - the caller does not exist yet. The
#  client therefore emits SIGNUP_ATTEMPT / SIGNUP_SUCCESS / SIGNUP_FAILURE, never a
#  LOGIN_SUCCESS, and a signup does not open a session on either side.
# ==========================================================================================
@app.route('/signup', methods=['POST'])
def signup():
    clean, problem = validate_signup()
    if problem:
        return makejson({"message": problem})

    taken = {a.account_number for a in Account.query.all()}
    from_number = allocate_account_number(taken)
    to_number = allocate_account_number(taken)
    if from_number is None or to_number is None:
        db_session.rollback()
        return makejson({"message": "Could not allocate accounts, please retry"})

    new_user = User(username=clean["username"],
                    password=clean["password"],
                    first_name=clean["first_name"],
                    last_name=clean["last_name"],
                    email=clean["email"],
                    phone=clean["phone"],
                    address=clean["address"])
    db_session.add(new_user)
    db_session.add(Account(account_number=from_number, type='from',
                           balance=SIGNUP_OPENING_BALANCE, user=clean["username"]))
    db_session.add(Account(account_number=to_number, type='to',
                           balance=SIGNUP_OPENING_BALANCE, user=clean["username"]))

    #  Two concurrent signups can pass the duplicate-username check at the same time, so
    #  the UNIQUE constraint is the authority here. Anything it raises is reported as a
    #  clean duplicate rather than a 500, and the partial insert is undone.
    try:
        db_session.commit()
    except IntegrityError:
        db_session.rollback()
        return makejson({"message": "Username already exists"})

    data = {"message": "User created successfully",
            "user": clean["username"],
            "from": from_number,
            "to": to_number,
            "opening_balance": SIGNUP_OPENING_BALANCE}

    print(makejson(data))

    return makejson(data)


# ==========================================================================================
#  Feature 1 - Account Details
# ==========================================================================================

@app.route('/getaccountdetails', methods=['POST'])
def getaccountdetails():
    """
    Feature 1 / ACCOUNT DETAILS.
    Returns the holder name and every account owned by the caller. Properly authorised:
    the credentials are verified and only the caller's own rows are returned.
    """
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials", "accounts": [],
                         "holder_name": ""})

    accounts = []
    for a in Account.query.filter(Account.user == u.username).all():
        accounts.append({"account_number": str(a.account_number),
                         "type": a.type,
                         "balance": a.balance,
                         "currency": "USD"})

    primary = None
    for a in accounts:
        if a["type"] == 'from':
            primary = a
            break
    if primary is None and accounts:
        primary = accounts[0]

    data = {
        "message": "Correct Credentials",
        "holder_name": (u.first_name or "") + " " + (u.last_name or ""),
        "customer_id": str(u.id),
        "account_number": primary["account_number"] if primary else "",
        "account_type": primary["type"] if primary else "",
        "balance": primary["balance"] if primary else 0,
        "currency": "USD",
        "accounts": accounts,
    }
    return makejson(data)


'''
Every account owned by the caller. Shared by Account Details and Deposit Money.
'''
@app.route('/getmyaccounts', methods=['POST'])
def getmyaccounts():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials", "accounts": []})

    accounts = []
    for a in Account.query.filter(Account.user == u.username).all():
        accounts.append({"account_number": str(a.account_number),
                         "type": a.type,
                         "balance": a.balance})
    return makejson({"message": "Correct Credentials", "accounts": accounts})


# ==========================================================================================
#  Feature 2 - Transaction History
# ==========================================================================================

@app.route('/gettransactions', methods=['POST'])
def gettransactions():
    """
    Feature 2 / TRANSACTION HISTORY.
    The client caches this list locally. Search and filtering happen on the device, which
    is where the intentional local SQL injection lives (RASP-VULN-002, see the Android
    source - nothing unsafe happens on this side).
    """
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials", "transactions": []})

    rows = Transaction.query.filter(Transaction.user == u.username) \
        .order_by(Transaction.id.desc()).all()

    return makejson({"message": "Correct Credentials",
                     "transactions": [t.values for t in rows]})


# ==========================================================================================
#  Feature 3 - Beneficiary Management
# ==========================================================================================

@app.route('/getbeneficiaries', methods=['POST'])
def getbeneficiaries():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials", "beneficiaries": []})

    rows = Beneficiary.query.filter(Beneficiary.user == u.username) \
        .order_by(Beneficiary.id.desc()).all()
    return makejson({"message": "Correct Credentials",
                     "beneficiaries": [b.values for b in rows]})


@app.route('/addbeneficiary', methods=['POST'])
def addbeneficiary():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials"})

    name = (request.form.get('name') or "").strip()
    number = (request.form.get('account_number') or "").strip()
    bank = (request.form.get('bank_name') or "").strip()
    kind = (request.form.get('account_type') or "").strip()

    if not name or not number:
        return makejson({"message": "Beneficiary name and account number are required"})

    b = Beneficiary(user=u.username, name=name, account_number=number,
                    bank_name=bank, account_type=kind, created_date=now_stamp())
    db_session.add(b)
    db_session.commit()
    return makejson({"message": "Beneficiary Added", "id": str(b.id)})


@app.route('/deletebeneficiary', methods=['POST'])
def deletebeneficiary():
    """
    Ownership IS checked here on purpose. The intentional weakness of this feature is
    RASP-VULN-003 (an exported, unprotected Android component) and it is kept on the
    client so that a single defect does not multiply across the whole feature.
    """
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials"})

    bid = as_int(request.form.get('id'))
    b = Beneficiary.query.filter(Beneficiary.id == bid).first() if bid is not None else None
    if not b or b.user != u.username:
        return makejson({"message": "Beneficiary not found"})

    db_session.delete(b)
    db_session.commit()
    return makejson({"message": "Beneficiary Deleted"})


# ==========================================================================================
#  Feature 4 - Bill Payment
# ==========================================================================================

@app.route('/getbillcategories', methods=['POST'])
def getbillcategories():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials", "categories": []})
    return makejson({"message": "Correct Credentials", "categories": BILL_CATEGORIES})


# ------------------------------------------------------------------------------------------
#  VULNERABILITY ID : RASP-VULN-004
#  FEATURE          : 4 - Bill Payment  (endpoint /paybill)
#  TYPE             : CWE-20 Improper Input Validation
#  COMPONENT        : AndroLabServer/app.py :: paybill()
#  EXPECTED GOOD    : a bill/account number of 6-20 digits and a strictly positive amount
#                     not exceeding the payer balance are accepted; anything else is
#                     rejected with "Invalid payment details".
#  ACTUAL BEHAVIOUR : neither the format of `bill_number` nor the sign/magnitude of
#                     `amount` is checked. Any string the caller sends is stored verbatim
#                     and the payment is always reported as successful.
#  REPRODUCE        :   adb shell am start -n com.android.insecurebankv2/.BillPaymentActivity
#                     or directly
#                     curl -d "username=dinesh&password=Dinesh@123\$&category=Water\
#                     &bill_number=' OR 1=1--&amount=-1&payer_account=123456789" \
#                     http://<host>:8888/paybill
#                     -> {"message":"Bill Payment Successful", ...}
#  SAFETY           : the value is only ever bound as a parameter of an INSERT, never
#                     concatenated into SQL, so this is a pure validation defect: it cannot
#                     execute code, cannot drop data and cannot break the application.
#                     Legitimate input is unaffected.
# ------------------------------------------------------------------------------------------
@app.route('/paybill', methods=['POST'])
def paybill():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials"})

    category = request.form.get('category') or ""
    bill_number = request.form.get('bill_number') or ""
    amount_raw = request.form.get('amount') or ""
    payer_account = request.form.get('payer_account') or ""

    # RASP-VULN-004: the ONLY thing that happens here is a best effort numeric coercion
    # used for the summary column. There is deliberately no length check, no charset
    # check, no "> 0" check and no "amount <= balance" check.
    try:
        amount_value = int(amount_raw)
    except (TypeError, ValueError):
        amount_value = 0

    reference = make_reference("BILL")
    pay = BillPayment(user=u.username, category=category, bill_number=bill_number,
                      amount=amount_raw, amount_value=amount_value,
                      payer_account=payer_account, status="SUCCESS",
                      reference=reference, paid_date=now_stamp())
    db_session.add(pay)

    # A bill payment is money leaving the payer account, so a transaction row is written
    # as well. Only an amount that is a real positive integer moves the balance; anything
    # else is recorded as a zero value movement so that a malformed request cannot drive
    # balances into an undefined state.
    account = account_or_none(payer_account)
    if account and amount_value and amount_value > 0:
        account.balance -= amount_value
        db_session.add(Transaction(user=u.username,
                                   account_number=str(account.account_number),
                                   type="BILL_PAYMENT", direction="DEBIT",
                                   amount=amount_value, counterparty=category,
                                   reference=reference, txn_date=now_stamp()))

    db_session.commit()

    return makejson({"message": "Bill Payment Successful",
                     "reference": reference,
                     "category": category,
                     "amount": amount_raw,
                     "bill_number": bill_number})


@app.route('/getbillhistory', methods=['POST'])
def getbillhistory():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials", "payments": []})

    rows = BillPayment.query.filter(BillPayment.user == u.username) \
        .order_by(BillPayment.id.desc()).all()
    return makejson({"message": "Correct Credentials",
                     "payments": [p.values for p in rows]})


# ==========================================================================================
#  Feature 5 - Profile Management
# ==========================================================================================

@app.route('/getprofile', methods=['POST'])
def getprofile():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials"})

    return makejson({"message": "Correct Credentials",
                     "username": u.username,
                     "first_name": u.first_name or "",
                     "last_name": u.last_name or "",
                     "full_name": ((u.first_name or "") + " " + (u.last_name or "")).strip(),
                     "email": u.email or "",
                     "phone": u.phone or "",
                     "address": u.address or ""})


@app.route('/updateprofile', methods=['POST'])
def updateprofile():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials"})

    first = (request.form.get('first_name') or "").strip()
    last = (request.form.get('last_name') or "").strip()
    email = (request.form.get('email') or "").strip()
    phone = (request.form.get('phone') or "").strip()
    address = (request.form.get('address') or "").strip()

    if first:
        u.first_name = first
    if last:
        u.last_name = last
    if email:
        u.email = email
    if phone:
        u.phone = phone
    if address:
        u.address = address

    db_session.commit()
    return makejson({"message": "Profile Updated"})


# ==========================================================================================
#  Feature 6 - Deposit Money
# ------------------------------------------------------------------------------------------
#  VULNERABILITY ID : RASP-VULN-006
#  FEATURE          : 6 - Deposit Money  (endpoint /deposit)
#  TYPE             : CWE-862 Missing Authorization + CWE-20 Improper Input Validation
#                     (business logic)
#  COMPONENT        : AndroLabServer/app.py :: deposit()
#  EXPECTED GOOD    : the server verifies that `account_number` belongs to the
#                     authenticated user, that `amount` is numeric, strictly positive and
#                     within an allowed ceiling.
#  ACTUAL BEHAVIOUR : the authenticated caller is never compared against the owner of
#                     `account_number`, and the sign/magnitude of `amount` is not checked.
#  REPRODUCE        : log in as dinesh, then credit an account that does not belong to him
#                     curl -d "username=dinesh&password=Dinesh@123\$&account_number=555555555&amount=5000" \
#                     http://<host>:8888/deposit
#                     -> balance of 555555555 (jack's account) grows by 5000.
#                     A negative amount reverses the direction of the movement.
#  SAFETY           : limited to this local research database; the account number must
#                     still exist, so a malformed request returns a clean error and the
#                     application never crashes. Nothing outside the test fixture is
#                     touched.
# ------------------------------------------------------------------------------------------
@app.route('/deposit', methods=['POST'])
def deposit():
    u = authenticate()
    if not u:
        return makejson({"message": "Wrong Credentials"})

    account_number = request.form.get('account_number') or ""
    amount_raw = request.form.get('amount') or ""

    account = account_or_none(account_number)
    if not account:
        return makejson({"message": "Account does not exist", "balance": 0})

    # RASP-VULN-006: no `account.user == u.username` check here on purpose, and the
    # amount is coerced without any range or sign validation.
    try:
        amount = int(amount_raw)
    except (TypeError, ValueError):
        amount = 0

    account.balance = (account.balance or 0) + amount

    reference = make_reference("DEP")
    db_session.add(Transaction(user=u.username,
                               account_number=str(account.account_number),
                               type="DEPOSIT",
                               direction="CREDIT" if amount >= 0 else "DEBIT",
                               amount=abs(amount),
                               counterparty="CASH DEPOSIT",
                               reference=reference,
                               txn_date=now_stamp()))
    db_session.commit()

    return makejson({"message": "Deposit Successful",
                     "account_number": str(account.account_number),
                     "balance": account.balance,
                     "reference": reference})


# ==========================================================================================

if __name__ == '__main__':
    port = DEFAULT_PORT_NO

    options, args = getopt.getopt(
        sys.argv[1:],
        "",
        ["help", "port="]
    )

    for op, arg1 in options:
        if op == "--help":
            usageguide()
            sys.exit(2)

        elif op == "--port":
            port = int(arg1)

    ensure_schema()

    if web is not None:
        urls = ("/.*", "app")
        apps = web.application(urls, globals())

    server = wsgi.Server(
        ("0.0.0.0", port),
        app,
        server_name='localhost'
    )

    print("The server is hosted on port:", port)

    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
