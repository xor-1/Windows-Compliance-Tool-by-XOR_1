import subprocess
import winreg

# Function to check for firewall status
def check_firewall_status():
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-NetFirewallProfile | Select-Object -Property Name, Enabled"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return "Error checking firewall status"
    except Exception as e:
        return f"Error checking firewall status: {e}"

# Function to check installed apps
def check_installed_apps():
    try:
        installed_apps = []
        
        # Check 64-bit apps
        result_64 = subprocess.run(
            ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"],
            capture_output=True,
            text=True
        )
        if result_64.returncode == 0:
            installed_apps += result_64.stdout.lower().splitlines()
        
        # Check 32-bit apps (for 64-bit systems)
        result_32 = subprocess.run(
            ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"],
            capture_output=True,
            text=True
        )
        if result_32.returncode == 0:
            installed_apps += result_32.stdout.lower().splitlines()
        
        # Filter empty or whitespace lines
        installed_apps = [app.strip() for app in installed_apps if app.strip()]

        # List all installed apps
        report = "Installed Apps:\n"
        for app in installed_apps:
            report += f"- {app}\n"

        return report
    except Exception as e:
        return f"Error checking installed apps: {e}"

# Function to check if antivirus is installed (e.g., Avast, Total Security, etc.)
def check_antivirus():
    try:
        # List of known antivirus products
        antivirus_list = ["Avast", "AVG", "McAfee", "Bitdefender", "Kaspersky", "Norton", "Total Security"]

        installed_apps = []
        result = subprocess.run(
            ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            installed_apps += result.stdout.lower().splitlines()

        result_32 = subprocess.run(
            ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName"],
            capture_output=True,
            text=True
        )
        if result_32.returncode == 0:
            installed_apps += result_32.stdout.lower().splitlines()
        
        # Check if any antivirus software is installed
        for app in installed_apps:
            for antivirus in antivirus_list:
                if antivirus.lower() in app.lower():
                    return f"Antivirus {antivirus} is installed."
        
        return "No antivirus software detected."

    except Exception as e:
        return f"Error checking antivirus status: {e}"

# Function to check app updates using winget
def check_app_updates():
    try:
        result = subprocess.run(
            ["winget", "upgrade", "--source", "winget"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            updates = result.stdout.splitlines()
            
            # Skip header lines and parse app details
            updates_report = "App Updates Available:\n"
            for line in updates[2:]:  # Skip first two lines (headers)
                if line.strip():  # Ignore empty lines
                    # Extract meaningful columns (Name, Version, etc.)
                    app_details = " ".join(line.split())
                    updates_report += f"- {app_details}\n"
            return updates_report.strip()
        else:
            return "Error checking app updates or no updates available."
    except Exception as e:
        return f"Error checking app updates: {e}"

# Function to check password length in registry
def check_security_settings():
    try:
        reg_path = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        reg_key = "MinimumPasswordLength"

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                password_length, _ = winreg.QueryValueEx(key, reg_key)
                if password_length >= 8:
                    return "Password policy is strong (8 characters or more)."
                else:
                    return f"Password policy is weak (less than 8 characters)."
        except FileNotFoundError:
            return "Password policy not set in the registry."
    except Exception as e:
        return f"Error checking security settings: {e}"

# Function to write results to a text file
def write_report_to_file(report, filename="compliance_report.txt"):
    try:
        with open(filename, "w") as file:
            file.write(report)
        print(f"Report saved to {filename}")
    except Exception as e:
        print(f"Error saving the report: {e}")

# Generating the report
report = ""

report += "\n--- Firewall Status ---\n"
report += check_firewall_status() + "\n"

report += "\n--- Installed Apps Check ---\n"
report += check_installed_apps() + "\n"

report += "\n--- Antivirus Check ---\n"
report += check_antivirus() + "\n"

report += "\n--- App Updates Check ---\n"
report += check_app_updates() + "\n"

report += "\n--- Security Settings Check (Password Length) ---\n"
report += check_security_settings() + "\n"

# Write the report to a file
write_report_to_file(report)
Explain
