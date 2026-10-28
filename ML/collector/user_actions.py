from config import find, tap, type_in, by_text, PKG
import screens as S
from appium.webdriver.common.appiumby import AppiumBy
from human_pauses import think, REVIEW_PAUSE, READ_PAUSE


# ------- Helper functions -----------
def open_tile(driver, label):
    tap(driver, by_text(label))
    think(READ_PAUSE)

def select_from_dropdown(driver, dropwon_id, tile_name):
    tap(driver, dropwon_id)
    tap(driver, by_text(tile_name))

def go_back(driver):
    think(1.5)      # glance at the result/confirmation, then leave
    driver.back()

# ------- Login and manage account actions -----------
def login(driver, user, pw):
    type_in(driver, S.LOGIN["username"], user)
    type_in(driver, S.LOGIN["password"], pw)
    tap(driver, S.LOGIN["login_btn"])

def make_typo(rng, text):
    """return a relasitc typo of the given text"""
    i = rng.randrange(len(text))
    typo_class = rng.choice(["drop", "double", "swap", "case"])

    # drop one char first
    if typo_class == "drop" and len(text) > 1:
        typo = text[:i] + text[i + 1:]
    elif typo_class == "double": # double the char at index i
        typo = text[:i] + text[i] + text[i:]
    elif typo_class == "swap" and len(text) > 1: # swap two consectuive chars
        i = min(i, len(text) - 2)
        typo = text[:i] + text[i + 1] + text[i] + text[i + 2: ]
    else: # swap case of the i-th letter
        typo = text[:i] + text[i].swapcase() + text[i + 1:]
    return typo if typo != text else text + text[-1]
    
def login_with_typos(driver, user, pw, rng = None , n_typos = 0):
    """login but with first n_typos first"""
    for _ in range(n_typos):
        login(driver, user, make_typo(rng, pw))
        think(3)  # think time (tries to remeber the password)
        find(driver, S.LOGIN["password"])

    login(driver, user, pw)

def update_profile(driver, email):
    open_tile(driver, S.TILE["profile"])
    type_in(driver, S.PROFILE["email"], email)
    tap(driver, S.PROFILE["save_btn"])
    go_back(driver)

def change_password_from_tile(driver, new_passw):
    open_tile(driver, S.TILE["change_password"])
    type_in(driver, S.CHANGE_PW["new_pw"], new_passw)
    think(REVIEW_PAUSE)
    tap(driver, S.CHANGE_PW["submit"])

#the app expect us to restart and login after some actions
def restart_and_login(driver, user, pw, rng=None, n_typos=0):
    driver.terminate_app(PKG)
    driver.activate_app(PKG)
    login_with_typos(driver, user, pw, rng, n_typos)

def view_account_detalis(driver):
    open_tile(driver, S.TILE["account_details"])
    find(driver, S.ACCOUNT["list"])
    tap(driver, S.ACCOUNT["refersh_btn"])
    go_back(driver)

# ------- Sign up -----------
def signup(driver, user, pw, first, last, email="", phone="", address=""):
    tap(driver, S.LOGIN["create_user"])
    type_in(driver, S.SIGNUP["username"], user)
    type_in(driver, S.SIGNUP["password"], pw)
    type_in(driver, S.SIGNUP["confirm"], pw)
    type_in(driver, S.SIGNUP["first_name"], first)
    type_in(driver, S.SIGNUP["last_name"], last)
    type_in(driver, S.SIGNUP["email"], email)
    type_in(driver, S.SIGNUP["phone"], phone)
    type_in(driver, S.SIGNUP["address"], address)
    tap(driver, S.SIGNUP["create_btn"])
    find(driver, S.LOGIN["password"]) 

# ----- Add & Transfer to beneficiary -------------
def add_beneficiary(driver, name, account, bank):
    open_tile(driver, S.TILE["beneficiaries"])
    type_in(driver, S.BENEFICIARY["name"], name)
    type_in(driver, S.BENEFICIARY["account"], account)
    type_in(driver, S.BENEFICIARY["bank"], bank)
    tap(driver, S.BENEFICIARY["add_btn"])
    go_back(driver)

def transfer_to_beneficiary(driver, amount, account_from, bene_name):
    open_tile(driver, S.TILE["transfer"])
    type_in(driver, S.TRANSFER["from"], account_from)
    tap(driver, S.TRANSFER["pick_bene"])
    tap(driver, by_text(bene_name))
    type_in(driver, S.TRANSFER["amount"], amount)
    think(REVIEW_PAUSE)
    tap(driver, S.TRANSFER["transfer_btn"])
    go_back(driver)

# ------ Deposite & Bill payment ------
def deposit(driver, account, amount):
    open_tile(driver, S.TILE["deposit"])
    type_in(driver, S.DEPOSIT["account_override"], account)
    type_in(driver, S.DEPOSIT["amount"], amount)
    think(REVIEW_PAUSE)
    tap(driver, S.DEPOSIT["confirm"])
    go_back(driver)


def pay_bill(driver, bill_category, from_account, bill_num, amount):
    open_tile(driver, S.TILE["bill_payment"])
    select_from_dropdown(driver, S.BILL["category"], bill_category)
    select_from_dropdown(driver, S.BILL["from_account"], from_account)
    type_in(driver, S.BILL["number"], bill_num)
    type_in(driver, S.BILL["amount"], amount)
    think(REVIEW_PAUSE)
    tap(driver, S.BILL["pay_btn"])
    go_back(driver)


# ---- Sync & Search from the transaction history ------
def sync_and_search_transaction_history(driver, keyword):
    open_tile(driver, S.TILE["transactions"])
    tap(driver, S.TRANSACTION["sync"])
    type_in(driver, S.TRANSACTION["search"], keyword)
    tap(driver, S.TRANSACTION["search_btn"])
    go_back(driver)

#------ set ip & port ------
def set_ip_and_port(driver, ip="10.0.2.2", port="8888"):
    tap(driver, (AppiumBy.ACCESSIBILITY_ID, "More options"))
    tap(driver, by_text("Preferences"))
    type_in(driver, S.PREFS["server_ip"], ip)
    type_in(driver, S.PREFS["server_port"], port)
    tap(driver, S.PREFS["submit"])

# ------ user action with mistakes ------------
def hide_keyboard(driver):
    try:
        if driver.is_keyboard_shown():
            driver.hide_keyboard()
    except Exception:
        pass

ABANDON_TILES = {"DEPOSIT": "deposit", "BILL": "bill_payment",
                 "BENEFICIARY": "beneficiaries", "TRANSFER": "transfer",
                 "PROFILE": "profile"}

def abandon_form(driver, state, field=None, text=""):
    """Open a tile, maybe right some text then close it before submitting anything"""
    open_tile(driver, S.TILE[ABANDON_TILES[state]])
    if field:
        type_in(driver, field, text)
    hide_keyboard(driver)       
    go_back(driver)