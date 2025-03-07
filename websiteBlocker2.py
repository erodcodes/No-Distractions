import os
import time
import psutil
import subprocess

# Path to the hosts file
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

# List of websites to block
blocked_sites = [
    "youtube.com"
]

# List of common browser executable names and their corresponding paths
BROWSERS = {
    "chrome.exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "firefox.exe": r"C:\Program Files\Mozilla Firefox\firefox.exe",
    "msedge.exe": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "brave.exe": r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    "opera.exe": r"C:\Users\%USERNAME%\AppData\Local\Programs\Opera\launcher.exe"
}

def flush_dns_cache():
    """Flush the DNS cache to apply changes immediately."""
    try:
        os.system("ipconfig /flushdns")
        print("DNS cache flushed successfully.")
    except Exception as e:
        print(f"Error flushing DNS cache: {e}")

def get_running_browsers():
    """Detect currently running browsers and return a list of them."""
    running_browsers = []
    for process in psutil.process_iter(attrs=["pid", "name"]):
        if process.info["name"] in BROWSERS:
            running_browsers.append(process.info["name"])
    return list(set(running_browsers))  # Remove duplicates

def restart_browsers():
    """Close and restart only the browsers that were previously open, restoring Firefox tabs."""
    running_browsers = get_running_browsers()
    
    if not running_browsers:
        print("No browsers were running.")
        return

    print("Closing browsers...")
    for process in psutil.process_iter(attrs=["pid", "name"]):
        if process.info["name"] in running_browsers:
            try:
                os.kill(process.info["pid"], 9)  # Force kill process
                print(f"Closed {process.info['name']}")
            except Exception as e:
                print(f"Error closing {process.info['name']}: {e}")

    # Wait a moment before reopening
    time.sleep(3)

    print("Reopening browsers...")
    for browser in running_browsers:
        browser_path = BROWSERS.get(browser)
        if browser_path:
            try:
                if browser == "firefox.exe":
                    subprocess.Popen([browser_path, "-new-instance", "-restore"], shell=True)
                else:
                    subprocess.Popen(browser_path, shell=True)
                print(f"Reopened {browser}")
            except Exception as e:
                print(f"Error reopening {browser}: {e}")
        else:
            print(f"Could not find the path for {browser}")

def block_websites():
    """Block websites by modifying the hosts file."""
    try:
        with open(HOSTS_PATH, "a") as file:
            for site in blocked_sites:
                file.write(f"\n127.0.0.1 {site}")
                file.write(f"\n127.0.0.1 www.{site}")
        print("Websites blocked successfully.")

        flush_dns_cache()
        restart_browsers()
    except PermissionError:
        print("Error: Permission denied. Run the script as administrator.")
    except Exception as e:
        print(f"An error occurred: {e}")

def unblock_websites():
    """Unblock websites by removing entries from the hosts file."""
    try:
        with open(HOSTS_PATH, "r") as file:
            lines = file.readlines()

        with open(HOSTS_PATH, "w") as file:
            for line in lines:
                if not any(site in line for site in blocked_sites):
                    file.write(line)
        print("Websites unblocked successfully.")

        flush_dns_cache()
        restart_browsers()
    except PermissionError:
        print("Error: Permission denied. Run the script as administrator.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    """Main function to choose blocking or unblocking."""
    print("1. Block Websites")
    print("2. Unblock Websites")
    choice = input("Enter your choice (1 or 2): ")

    if choice == "1":
        block_websites()
    elif choice == "2":
        unblock_websites()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()

#implement next:
#gui for interactivity