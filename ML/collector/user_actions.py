import time
import random
from config import find, tap, type_in, start_driver, by_text
import screens as S
from appium.webdriver.common.appiumby import AppiumBy

# ------- Helper functions -----------
def open_tile(driver, label):
    tap(driver, by_text(label))

def select_from_dropdown(driver, dropwon_id, tile_name):
    tap(driver, dropwon_id)
    tap(driver, by_text(tile_name))

def human_pause(min_seconds=0.5, max_seconds=2.0):
    #generate random number (sleep duration)
    delay = random.uniform(min_seconds, max_seconds)
    time.sleep(delay)

# ------- Login and manage account actions -----------
def login(driver, user, pw):
    type_in(driver, S.LOGIN["username"], user)
    type_in(driver, S.LOGIN["password"], pw)
    tap(driver, S.LOGIN["login_btn"])

def update_profile(driver, email):
    open_tile(driver, S.TILE["profile"])
    type_in(driver, S.PROFILE["email"], email)
    tap(driver, S.PROFILE["save_btn"])
    driver.back()

def change_password_from_tile(driver, new_passw):
    open_tile(driver, S.TILE["change_password"])
    type_in(driver, S.CHANGE_PW["new_pw"], new_passw)
    tap(driver, S.CHANGE_PW["submit"])
    driver.back()

def view_account_detalis(driver):
    open_tile(driver, S.TILE["account_details"])
    find(driver, S.ACCOUNT["list"])
    tap(driver, S.ACCOUNT["refersh_btn"])
    driver.back()

# ----- Add & Transfer to beneficiary -------------
def add_beneficiary(driver, name, account, bank):
    open_tile(driver, S.TILE["beneficiaries"])
    type_in(driver, S.BENEFICIARY["name"], name)
    type_in(driver, S.BENEFICIARY["account"], account)
    type_in(driver, S.BENEFICIARY["bank"], bank)
    tap(driver, S.BENEFICIARY["add_btn"])
    driver.back()

def transfer_to_beneficiary(driver, amount, account_from, bene_name):
    open_tile(driver, S.TILE["transfer"])
    type_in(driver, S.TRANSFER["from"], account_from)
    tap(driver, S.TRANSFER["pick_bene"])
    tap(driver, by_text(bene_name))
    type_in(driver, S.TRANSFER["amount"], amount)
    tap(driver, S.TRANSFER["transfer_btn"])
    driver.back()

# ------ Deposite & Bill payment ------
def deposit(driver, account, amount):
    open_tile(driver, S.TILE["deposit"])
    type_in(driver, S.DEPOSIT["account_override"], account)
    type_in(driver, S.DEPOSIT["amount"], amount)
    tap(driver, S.DEPOSIT["confirm"])
    driver.back()

def pay_bill(driver, bill_category, from_account, bill_num, amount):
    open_tile(driver, S.TILE["bill_payment"])
    select_from_dropdown(driver, S.BILL["category"], bill_category)
    select_from_dropdown(driver, S.BILL["from_account"], from_account)
    type_in(driver, S.BILL["number"], bill_num)
    type_in(driver, S.BILL["amount"], amount)
    tap(driver, S.BILL["pay_btn"])
    driver.back()

# ---- Sync & Search from the transaction history ------
def sync_and_search_transaction_history(driver, keyword):
    open_tile(driver, S.TILE["transactions"])
    tap(driver, S.TRANSACTION["sync"])
    type_in(driver, S.TRANSACTION["search"], keyword)
    tap(driver, S.TRANSACTION["search_btn"])
    driver.back()

#------ set ip & port ------
def set_ip_and_port(driver, ip="10.0.2.2", port="8888"):
    tap(driver, (AppiumBy.ACCESSIBILITY_ID, "More options"))
    tap(driver, by_text("Preferences"))
    type_in(driver, S.PREFS["server_ip"], ip)
    type_in(driver, S.PREFS["server_port"], port)
    tap(driver, S.PREFS["submit"])