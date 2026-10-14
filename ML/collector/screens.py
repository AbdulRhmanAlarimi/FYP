from appium.webdriver.common.appiumby import AppiumBy
from config import PKG

def rid(name):
    """ get pakge:id/name"""
    return (AppiumBy.ID, f"{PKG}:id/{name}")

# --- Pages elements ---
# Appium Inspector page elements ids

LOGIN = {
    "username":    rid("loginscreen_username"),
    "password":    rid("loginscreen_password"),
    "login_btn":   rid("login_button"),
    "create_user": rid("button_CreateUser"),   
}
PREFS = {  
    "server_ip": rid("edittext_serverip"),
    "server_port": rid("edittext_serverport"),
    "submit": rid("submitPref_button") 
}
TILE = {      
    "account_details": "Account Details",
    "transactions":    "Transaction History",
    "beneficiaries":   "Beneficiaries",
    "bill_payment":    "Bill Payment",
    "profile":         "Profile",
    "deposit":         "Deposit Money",    
    "transfer":        "Transfer",
    "change_password" : "Change Password"
}
ACCOUNT = {
    "refresh": rid("button_refresh"),
    "list": rid("listView_accounts"),
    "refersh_btn": rid("button_refresh") 
}
TRANSACTION = {
    "search": rid("editText_search"),
    "search_btn": rid("button_search"),
    "sync": rid("button_sync"),
    "show_all": rid("button_showAll"),
    "list": rid("listView_transactions") 
}
BENEFICIARY = { 
    "name": rid("editText_beneName"), 
    "account": rid("editText_beneAccount"),
    "bank": rid("editText_beneBank"), 
    "add_btn": rid("button_addBeneficiary") 
}
TRANSFER = { 
    "amount": rid("editText_amount"),
    "pick_bene": rid("button_PickBeneficiary"),
    "transfer_btn": rid("button_Transfer"), 
    "from": rid("editText_from"), 
    "to": rid("editText_to") 
}
BILL = { 
    "category": rid("spinner_category"),
    "from_account": rid("spinner_payerAccount"),
    "number": rid("editText_billNumber"),
    "amount": rid("editText_billAmount"),
    "pay_btn": rid("button_payBill") 
}
PROFILE = { 
    "email": rid("editText_email"), 
    "save_btn": rid("button_saveProfile"),
    "change_pw_btn": rid("button_changePassword") 
}
CHANGE_PW = { 
    "new_pw": rid("editText_newPassword"),
    "submit": rid("button_newPasswordSubmit") 
}
DEPOSIT = { 
    "account_override": rid("editText_accountOverride"),
    "amount": rid("editText_depositAmount"), 
    "confirm": rid("button_deposit") 
}
