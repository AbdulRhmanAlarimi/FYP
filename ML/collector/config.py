from appium import webdriver
from appium.options.android import UiAutomator2Options
from appium.webdriver.common.appiumby import AppiumBy
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from human_pauses import think, TAP_PAUSE, FORM_PAUSE

#not related note: android virtual mc listen to local host 10.0.2.2
APPIUM_URL = "http://127.0.0.1:4723" # appium server url
PKG = "com.android.insecurebankv2" 
DEVICE = "emulator-5554" # emulator id
LOGIN_ACT = ".LoginActivity"

# configure and start the appium android driver 
def start_driver():
    options = UiAutomator2Options()
    options.device_name = DEVICE
    options.platform_name = "Android"
    options.app_package = PKG
    options.app_activity = LOGIN_ACT
    options.auto_grant_permissions = True # grant the app's declared premissions
    options.no_reset = True          # keep app data (server IP, db)
    driver = webdriver.Remote(
        APPIUM_URL,
        options=options
    )

    dismiss_old_sdk_dialog(driver)
    return driver

# ----- helper functions -----
def find(driver, locator, timeout = 15):
    # elements need sometime to load, so we need to wait
    return WebDriverWait(driver, timeout).until(EC.presence_of_element_located(locator))

def tap(driver, locator, timeout = 15):
    think(TAP_PAUSE)
    element = WebDriverWait(driver, timeout).until(EC.element_to_be_clickable(locator))
    element.click()
    return 

def type_in(driver, locator, text, timeout=15):
    think(FORM_PAUSE)
    element = find(driver, locator, timeout)
    element.clear()
    element.send_keys(str(text))
    # check that the emualtor's keyboard didn't autocompelete anything
    if element.text != str(text):
        driver.execute_script("mobile: replaceElementValue", {"elementId": element.id, "text": str(text)})

def by_text(text):
    return (AppiumBy.XPATH, f'//*[@text="{text}"]')

# close the old sdk dialog, when the app start
def dismiss_old_sdk_dialog(driver):
    try:
        locator = (AppiumBy.ID, "android:id/button1")
        tap(driver, locator, timeout=3)
    except TimeoutException:
        pass  
