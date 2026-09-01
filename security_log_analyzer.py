from collections import Counter
import re


LOG_FILE = "security.log"
FAILED_LOGIN_THRESHOLD = 3


def analyze_log(filename):
    failed_logins = []
    successful_logins = []
    ip_addresses = []

    with open(filename, "r") as file:
        for line in file:
            ip_match = re.search(r"ip=(\d+\.\d+\.\d+\.\d+)", line)

            if ip_match:
                ip = ip_match.group(1)
                ip_addresses.append(ip)

            if "FAILED_LOGIN" in line:
                failed_logins.append(line.strip())

            elif "SUCCESS_LOGIN" in line:
                successful_logins.append(line.strip())

    return failed_logins, successful_logins, ip_addresses


def detect_suspicious_ips(failed_logins):
    failed_ips = []

    for line in failed_logins:
        match = re.search(r"ip=(\d+\.\d+\.\d+\.\d+)", line)

        if match:
            failed_ips.append(match.group(1))

    ip_counts = Counter(failed_ips)

    suspicious_ips = {
        ip: count
        for ip, count in ip_counts.items()
        if count >= FAILED_LOGIN_THRESHOLD
    }

    return suspicious_ips


def generate_report(failed_logins, successful_logins, suspicious_ips):
    report = []

    report.append("===== SECURITY LOG ANALYSIS REPORT =====")
    report.append("")

    report.append(f"Total Failed Login Attempts: {len(failed_logins)}")
    report.append(f"Total Successful Logins: {len(successful_logins)}")
    report.append("")

    report.append("Suspicious IP Addresses:")
    
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            report.append(
                f"- {ip}: {count} failed login attempts"
            )
    else:
        report.append("- No suspicious IP addresses detected.")

    report.append("")
    report.append("========================================")

    return "\n".join(report)


def main():
    try:
        failed_logins, successful_logins, ip_addresses = analyze_log(LOG_FILE)

        suspicious_ips = detect_suspicious_ips(failed_logins)

        report = generate_report(
            failed_logins,
            successful_logins,
            suspicious_ips
        )

        print(report)

        with open("report.txt", "w") as file:
            file.write(report)

        print("\nReport saved to report.txt")

    except FileNotFoundError:
        print(f"Error: {LOG_FILE} was not found.")


if __name__ == "__main__":
    main()