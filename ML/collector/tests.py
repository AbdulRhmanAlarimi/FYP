""" Tests for some user action flows """
from config import start_driver
from user_actions import *

TEST_USER = "dinesh"
TEST_PASS = "Dinesh@123$"

def test_update_profile(driver, user, passw):
    new_email = "good_email@gmail.com"
    new_passw = passw

    login(driver, user, passw)
    human_pause()
    update_profile(driver, new_email)
    view_account_detalis(driver)
    change_password_from_tile(driver, new_passw)

def test_add_benficiary_and_transfer(driver, user, passw):
    beneficiary_name = "salim"
    account_number = "2345"
    bank_name = "BankSalalah"
    from_account = "888888888"

    login(driver, user, passw)
    human_pause()
    add_beneficiary(driver, beneficiary_name, account_number, bank_name)
    transfer_to_beneficiary(driver, 4, from_account , beneficiary_name)
    human_pause()
    sync_and_search_transaction_history(driver, account_number)

def test_deposit(driver, user, passw):
    account_number = "123456789"
    amount = 20

    login(driver, user, passw)
    view_account_detalis(driver)
    deposit(driver, account_number, amount)
    human_pause()
    view_account_detalis(driver)

def test_pay_bill(driver, user, passw):
    bill_category = "Water"
    from_account = "123456789"
    bill_num = 123
    amount = 20

    login(driver, user, passw)
    pay_bill(driver, bill_category, from_account, bill_num, amount)
    view_account_detalis(driver)

def main():
    driver = start_driver()
    set_ip_and_port(driver)

    try:
        test_add_benficiary_and_transfer(driver, TEST_USER, TEST_PASS)
    finally:
        driver.quit()
    
if __name__ == "__main__":
    main()
