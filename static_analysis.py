import os
import re
from androguard.misc import AnalyzeAPK


def check_hardcoded_secrets(dvm):
    """Detects hardcoded secrets like API keys, passwords, or tokens in the APK."""
    secrets = []
    patterns = [r'key', r'password', r'token', r'api[_-]?key']

    try:
        for string in dvm.get_strings():
            if any(re.search(pattern, string, re.IGNORECASE) for pattern in patterns):
                secrets.append(string)
    except AttributeError:
        return ["Error: Failed to retrieve strings from APK."]

    return secrets


def check_exported_components(apk):
    """Finds exported activities, services, and receivers that lack protection."""
    vulnerabilities = []

    try:
        for activity in apk.get_activities():
            if apk.is_activity_exported(activity) and not apk.get_activity_permissions(activity):
                vulnerabilities.append(f"Exported activity without protection: {activity}")

        for service in apk.get_services():
            if apk.is_service_exported(service) and not apk.get_service_permissions(service):
                vulnerabilities.append(f"Exported service without protection: {service}")

        for receiver in apk.get_receivers():
            if apk.is_receiver_exported(receiver) and not apk.get_receiver_permissions(receiver):
                vulnerabilities.append(f"Exported receiver without protection: {receiver}")

    except AttributeError:
        return ["Error: Could not analyze exported components."]

    return vulnerabilities


def check_debuggable(apk):
    """Checks if the APK is built in debug mode."""
    try:
        return "Application is debuggable." if apk.is_debuggable() else None
    except AttributeError:
        return "Error: Unable to determine if the application is debuggable."


def check_insecure_network(dvm):
    """Finds hardcoded insecure network requests (HTTP instead of HTTPS)."""
    network_issues = []

    try:
        for string in dvm.get_strings():
            if string.startswith("http://127.0.0.1:5000/"):
                network_issues.append(f"Insecure network usage: {string}")
    except AttributeError:
        return ["Error: Failed to retrieve network strings."]

    return network_issues


def analyze_apk(file_path):
    """Analyzes an APK file for security vulnerabilities."""
    if not os.path.exists(file_path):
        return {"error": f"APK file not found: {file_path}"}

    try:
        result = AnalyzeAPK(file_path)

        # Handle potential unpacking issues
        if not isinstance(result, tuple) or len(result) != 3:
            return {"error": "AnalyzeAPK did not return expected values."}

        apk, dvm, analysis = result

        results = {
            "permissions": apk.get_permissions(),
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "vulnerabilities": []
        }

        checks = [
            ("Hardcoded Secrets", check_hardcoded_secrets(dvm)),
            ("Exported Components", check_exported_components(apk)),
            ("Debuggable Build", [check_debuggable(apk)] if check_debuggable(apk) else []),
            ("Insecure Network", check_insecure_network(dvm)),
        ]

        for check_name, issues in checks:
            if issues:
                results["vulnerabilities"].extend([f"{check_name}: {issue}" for issue in issues])

        return results
    except Exception as e:
        return {"error": str(e)}


# **Example Usage**
apk_path = r"C:\Users\vinay\PycharmProjects\static_apk_analyzer\InsecureShop.apk"

if not os.path.exists(apk_path):
    print(f"Error: APK file not found at {apk_path}")
else:
    analysis_results = analyze_apk(apk_path)
    print(analysis_results)
