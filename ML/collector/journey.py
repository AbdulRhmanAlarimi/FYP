from user_actions import *
from config import start_driver
from faker import Faker

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

def go_through_full_session(driver, rng, user_input, transitions, payees, max_steps):
    path, steps = [], 0
    state = pick_next_state(rng, "START", transitions)

    while state != "END" and steps < max_steps:
        path.append(state)
        run_activity(driver, rng, user_input, state, payees)
        # think(trng, 2.0)                              
        steps += 1
        state = pick_next_state(rng, state, transitions)
    return path

# --------------- Two user types flow ------------------

def login_session_flow(seed, user="dinesh", pw="Dinesh@123$", max_steps=10, debug=False):
    rng = random.Random(seed)
    user_input, payees = UserInput(seed), []
    driver = start_driver()
    try:
        set_ip_and_port(driver)
        login(driver, user, pw)
        think(3)
        path = go_through_full_session(driver, rng, user_input, FULL_TRANSITIONS, payees, max_steps)
    finally:
        driver.quit()

    if debug:
        print(f"seed:{seed} [login {user}] " + " -> ".join(path))
    return path

def signup_session_flow(seed, max_steps = 4, debug = False):
    rng = random.Random(seed)
    user_input, payees = UserInput(seed), []
    username = user_input.username()      
    password = user_input.password()
    first    = user_input.first_name()
    last     = user_input.last_name()
    email    = user_input.email()
    driver = start_driver()
    try:
        set_ip_and_port(driver)
        signup(driver, username, 
               password, first, 
               last, email)
        restart_and_login(driver, username, password)
        think(3)
        path = go_through_full_session(driver, rng, user_input, NEWUSER_TRANSITIONS, payees, max_steps)
    finally:
        driver.quit()

    if debug:
        print(f"seed:{seed} [signup {username}] " + " -> ".join(path))
    return path

# ----------- Entry point (decide the user type) -----------------
def start_journey(seed, signup_rate=0.15, debug = False):
    """collect.py calls this ~85% as logins, ~15% new-user signups"""

    if random.Random(seed + 999).random() < signup_rate:
                return signup_session_flow(seed, debug=debug)

    return login_session_flow(seed, debug=debug)