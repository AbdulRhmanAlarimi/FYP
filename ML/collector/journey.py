import random
from user_actions import *
from config import start_driver
from faker import Faker
from human_pauses import seed_time
import screens as S

# --------------------- Inputs ------------------------
DINESH_ACCOUNTS = ["123456789", "888888888", "666666666"]
PAYEE_ACCOUNTS  = ["555555555", "987654321", "999999999"]
VALID_BANKS     = ["Bank Muscat", "NBO", "Sohar Bank"]
BILL_CATEGORIES = ["Electricity", "Water", "Mobile Postpaid", "Broadband",
                   "Insurance Premium", "Credit Card"]
SEARCH_TERMS    = ["", "Transfer", "Deposit", "Bill", "Water", "Electricity"]

class UserInput:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.fake = Faker(); Faker.seed(seed)
    def name(self):
        return self.fake.name()
    def first_name(self):
        return self.fake.first_name()
    def last_name(self):
            return self.fake.last_name()
    def email(self):
        return self.fake.email()
    def username(self):
        return self.fake.user_name()[:12] + str(self.rng.randint(100, 999))
    def password(self):
        return self.fake.password()
    
def amount(rng):
    r = rng.random()
    if r < 0.75: return rng.randrange(5, 100)
    if r < 0.97: return rng.randrange(100, 500)
    return rng.randrange(500, 1000)

# -------------------- User mistakes -----------------------------
LOGIN_TYPO_RATE = 0.10 # % of logins with typo
SECOND_TYPO_RATE = 0.25 
ABANDON_RATE = 0.07 # chance of filling some form then not submitting
FORM_STATES = {"DEPOSIT", "BILL", "BENEFICIARY", "TRANSFER", "PROFILE"}
MISTAKE_SEED_OFFSET = 7777

def pick_typos(mrng):
    if mrng.random() >= LOGIN_TYPO_RATE:
        return 0
    return 2 if mrng.random() < SECOND_TYPO_RATE else 1

def abandon_partial(mrng, user_input, state):
    """ what the user had typed before he stopped filling the form (None, "") = just looked and left"""
    if mrng.random() < 0.4:
        return None, ""
    if state == "DEPOSIT":
        return S.DEPOSIT["amount"], str(amount(mrng))
    if state == "TRANSFER":
        return S.TRANSFER["amount"], str(amount(mrng))
    if state == "BILL":
        return S.BILL["number"], str(mrng.randint(100, 99999))
    if state == "BENEFICIARY":
        return S.BENEFICIARY["name"], user_input.first_name()
    if state == "PROFILE":
        email = user_input.email()
        return S.PROFILE["email"], email[:mrng.randint(3, 8)]
    return None, ""

# --------------------- navigation tables ------------------------

## flow states in the app:
# we did divide the states into two classes (for new users and for loged in user)
# each state containt a list of (next_state, weight) pairs example "START" : ("ACCOUNT", 5) .....

# this work for loged in user
FULL_TRANSITIONS = {
    "START":     [("ACCOUNT",5),("HISTORY",3),("DEPOSIT",2),("BILL",2),("TRANSFER",2),("BENEFICIARY",1),("PROFILE",1)],
    "ACCOUNT":   [("HISTORY",3),("TRANSFER",2),("DEPOSIT",2),("BILL",1),("PROFILE",1),("END",3)],
    "HISTORY":   [("ACCOUNT",2),("TRANSFER",1),("BILL",1),("END",4)],
    "BENEFICIARY": [("TRANSFER",6),("ACCOUNT",1),("END",1)],
    "TRANSFER": [("HISTORY",3),("ACCOUNT",2),("BENEFICIARY",1),("DEPOSIT",1),("END",3)],
    "BILL":     [("HISTORY",2),("ACCOUNT",1),("END",4)],
    "PROFILE":  [("ACCOUNT",1),("END",5)],
    "DEPOSIT":  [("ACCOUNT",3),("HISTORY",2),("END",3)],
}
# new users flows
NEWUSER_TRANSITIONS = {
    "START":   [("ACCOUNT",4),("PROFILE",2),("HISTORY",2),("END",2)],
    "ACCOUNT": [("HISTORY",2),("PROFILE",1),("END",4)],
    "HISTORY": [("ACCOUNT",1),("END",4)],
    "PROFILE": [("ACCOUNT",1),("END",4)],
}

# ---------------- Applying full sessions --------------------

# applying one state
def run_activity(driver, rng, input, state, payees):
    if state == "ACCOUNT":
        view_account_detalis(driver)
    if state == "HISTORY":
        sync_and_search_transaction_history(driver, rng.choice(SEARCH_TERMS))
    if state == "PROFILE":
        update_profile(driver, input.email())
    if state == "BENEFICIARY":
        name = input.name()
        add_beneficiary(driver, name, rng.choice(PAYEE_ACCOUNTS), rng.choice(VALID_BANKS))
        payees.append(name)
    if state == "TRANSFER":
        if not payees:
            name = input.name()
            add_beneficiary(driver, name, rng.choice(PAYEE_ACCOUNTS), rng.choice(VALID_BANKS))
            payees.append(name)
        transfer_to_beneficiary(driver, str(amount(rng)),
                                rng.choice(DINESH_ACCOUNTS), rng.choice(payees))
    if state == "BILL":
        pay_bill(driver, rng.choice(BILL_CATEGORIES), rng.choice(DINESH_ACCOUNTS),
                 str(rng.randint(1000000, 9999999)), str(amount(rng)))
    if state == "DEPOSIT":
        deposit(driver, rng.choice(DINESH_ACCOUNTS), str(amount(rng)))

def pick_next_state(rng, state, transition):
    # pick next state from the list of the next posibile by weighted by thier wieght
    opts = transition[state]
    states  = [s for s, _ in opts]
    weights = [w for _, w in opts]

    return rng.choices(states, weights = weights, k = 1)[0]

def go_through_full_session(driver, rng, mrng, user_input, transitions, payees, max_steps):
    path, steps, n_mistakes = [], 0, 0
    state = pick_next_state(rng, "START", transitions)

    while state != "END" and steps < max_steps:
        if state in FORM_STATES and mrng.random() < ABANDON_RATE:
            field, text = abandon_partial(mrng, user_input, state)
            abandon_form(driver, state, field, text)
            n_mistakes += 1
        else:
            run_activity(driver, rng, user_input, state, payees)
        path.append(state)                              
        steps += 1
        state = pick_next_state(rng, state, transitions)
    return path, n_mistakes

# --------------- Two user types flow ------------------

def login_session_flow(seed, user="dinesh", pw="Dinesh@123$", max_steps=10, debug=False):
    rng = random.Random(seed)
    mrng = random.Random(seed + MISTAKE_SEED_OFFSET)
    user_input, payees = UserInput(seed), []
    driver = start_driver()
    try:
        n_typos = pick_typos(mrng)
        login_with_typos(driver, user, pw, mrng, n_typos)
        think(3)
        path, n_mistakes = go_through_full_session(driver, rng, mrng, user_input, 
                                       FULL_TRANSITIONS, payees, max_steps)
    finally:
        driver.quit()

    if debug:
        print(f"seed:{seed} [login {user}] " + " -> ".join(path))
    return path, n_typos + n_mistakes

def signup_session_flow(seed, max_steps = 4, debug = False):
    rng = random.Random(seed)
    mrng = random.Random(seed + MISTAKE_SEED_OFFSET)
    user_input, payees = UserInput(seed), []
    username = user_input.username()      
    password = user_input.password()
    first    = user_input.first_name()
    last     = user_input.last_name()
    email    = user_input.email()
    driver = start_driver()
    try:
        signup(driver, username, 
               password, first, 
               last, email)
        n_typos = pick_typos(mrng)
        restart_and_login(driver, username, password, mrng, n_typos)
        think(3)
        path, n_mistakes = go_through_full_session(driver, rng, mrng, user_input, NEWUSER_TRANSITIONS, payees, max_steps)
    finally:
        driver.quit()

    if debug:
        print(f"seed:{seed} [signup {username}] " + " -> ".join(path))
    return path, n_mistakes + n_typos

# ----------- Entry point (decide the user type) -----------------
def start_journey(seed, signup_rate=0.15, debug = False):
    """collect.py calls this ~85% as logins, ~15% new-user signups"""

    seed_time(seed) # makes the pause lengths reproducible for this seed

    if random.Random(seed + 999).random() < signup_rate:
                return signup_session_flow(seed, debug=debug)

    return login_session_flow(seed, debug=debug)