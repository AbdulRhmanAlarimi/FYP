import subprocess, os
#from journey import benign_journey

# directory of the Android-InsecureBankv2 repo
ROOT_DIR = os.path.expanduser("~/.../FYP/Android-InsecureBankv2-master")
PKG = "com.android.insecurebankv2"
RESET_BACKEND = False

def reset_backend():
    """Put api data back to their seeded state"""
    subprocess.run(["Python3", "tools/verify_features.py"], cwd=ROOT_DIR, check=True)

def clean_virtual_device():
    """Start fresh virutal device"""
    subprocess.run(["adb", "shell", "am", "force-stop", PKG], check=True) # kill the app and make the next lunch start clean
    subprocess.run(["adb", "logcat", "-c"], check=True) # clear the log buffer

def run_one_flow(seed):
    if RESET_BACKEND:
        reset_backend()
    clean_virtual_device()
    #benign_journey(seed)

def run_batch(num_flows):
    for i in range(num_flows):
        print(f"---------- session {i + 1} / {num_flows} ----------")
        try:
            run_one_flow(i)
        except Exception as e:
            print(f"Session {i} falied:{e}")

if __name__ == "__main__":
    num_flows = int(input("Number of user flows: "))
    run_batch(num_flows)