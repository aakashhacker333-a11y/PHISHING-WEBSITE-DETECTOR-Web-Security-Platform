from flask import Flask, render_template, request
import re
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

DATABASE = "phishing.db"


# ================= DATABASE =================

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def create_database():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            status TEXT NOT NULL,
            reasons TEXT,
            checked_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ================= PHISHING DETECTION =================

def check_phishing(url):

    reasons = []
    checks = []
    score = 0

    url = url.strip()
    url_lower = url.lower()


    # ================= URL FORMAT =================

    if not re.match(r"^https?://", url_lower):

        checks.append({
            "name": "URL Format",
            "status": "warning",
            "message": "URL does not start with HTTP or HTTPS."
        })

        reasons.append(
            "URL does not use a standard HTTP/HTTPS format."
        )

        score += 1

    else:

        checks.append({
            "name": "URL Format",
            "status": "safe",
            "message": "Valid HTTP/HTTPS format detected."
        })


    # ================= URL LENGTH =================

    if len(url) > 75:

        score += 1

        reasons.append(
            "URL is unusually long."
        )

        checks.append({
            "name": "URL Length",
            "status": "danger",
            "message": "URL is unusually long."
        })

    else:

        checks.append({
            "name": "URL Length",
            "status": "safe",
            "message": "URL length appears normal."
        })


    # ================= @ SYMBOL =================

    if "@" in url:

        score += 2

        reasons.append(
            "URL contains an @ symbol."
        )

        checks.append({
            "name": "@ Symbol",
            "status": "danger",
            "message": "Suspicious @ symbol detected."
        })

    else:

        checks.append({
            "name": "@ Symbol",
            "status": "safe",
            "message": "No @ symbol detected."
        })


    # ================= IP ADDRESS =================

    ip_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"

    is_ip = re.search(
        ip_pattern,
        url_lower
    )

    if is_ip:

        score += 2

        reasons.append(
            "URL uses an IP address instead of a domain name."
        )

        checks.append({
            "name": "IP Address",
            "status": "danger",
            "message": "Website uses an IP address."
        })

    else:

        checks.append({
            "name": "IP Address",
            "status": "safe",
            "message": "Normal domain name detected."
        })


    # ================= HTTPS =================

    if url_lower.startswith("https://"):

        checks.append({
            "name": "HTTPS",
            "status": "safe",
            "message": "Secure HTTPS connection detected."
        })

    else:

        score += 1

        reasons.append(
            "Website does not use HTTPS."
        )

        checks.append({
            "name": "HTTPS",
            "status": "danger",
            "message": "Website does not use HTTPS."
        })


    # ================= SUSPICIOUS WORDS =================

    suspicious_words = [

        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "bank",
        "confirm",
        "signin",
        "security",
        "payment",
        "wallet",
        "credential"

    ]

    found_words = []

    for word in suspicious_words:

        if word in url_lower:
            found_words.append(word)


    if found_words:

        score += 1

        reasons.append(
            "URL contains suspicious words: "
            + ", ".join(found_words)
        )

        checks.append({
            "name": "Suspicious Keywords",
            "status": "danger",
            "message": "Found: " + ", ".join(found_words)
        })

    else:

        checks.append({
            "name": "Suspicious Keywords",
            "status": "safe",
            "message": "No suspicious keywords detected."
        })


    # ================= URL SHORTENER =================

    shortening_services = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "shorturl.at",
        "cutt.ly"

    ]

    shortener_found = None

    for service in shortening_services:

        if service in url_lower:

            shortener_found = service
            break


    if shortener_found:

        score += 1

        reasons.append(
            "URL uses a URL shortening service: "
            + shortener_found
        )

        checks.append({
            "name": "URL Shortener",
            "status": "danger",
            "message": "Shortener detected: "
                       + shortener_found
        })

    else:

        checks.append({
            "name": "URL Shortener",
            "status": "safe",
            "message": "No common URL shortener detected."
        })


    # ================= SPECIAL CHARACTERS =================

    if "_" in url:

        score += 1

        reasons.append(
            "URL contains an underscore."
        )

        checks.append({
            "name": "Special Characters",
            "status": "danger",
            "message": "Underscore detected in URL."
        })

    else:

        checks.append({
            "name": "Special Characters",
            "status": "safe",
            "message": "No suspicious underscore detected."
        })


    # ================= MULTIPLE HYPHENS =================

    hyphen_count = url.count("-")

    if hyphen_count >= 3:

        score += 1

        reasons.append(
            "URL contains multiple hyphens."
        )

        checks.append({
            "name": "Hyphen Usage",
            "status": "warning",
            "message": "Multiple hyphens detected."
        })

    else:

        checks.append({
            "name": "Hyphen Usage",
            "status": "safe",
            "message": "Normal hyphen usage detected."
        })


    # ================= SUBDOMAINS =================

    if not is_ip:

        try:

            parsed = urlparse(url)

            domain = parsed.netloc

            domain = domain.split(":")[0]

            parts = domain.split(".")


            if len(parts) >= 4:

                score += 1

                reasons.append(
                    "URL contains many subdomains."
                )

                checks.append({
                    "name": "Subdomain Structure",
                    "status": "danger",
                    "message": "Multiple subdomains detected."
                })

            else:

                checks.append({
                    "name": "Subdomain Structure",
                    "status": "safe",
                    "message": "Normal domain structure detected."
                })

        except Exception:

            checks.append({
                "name": "Subdomain Structure",
                "status": "warning",
                "message": "Unable to fully analyze domain structure."
            })

    else:

        checks.append({
            "name": "Subdomain Structure",
            "status": "warning",
            "message": "Subdomain check skipped for IP address."
        })


    # ================= EXCESSIVE SPECIAL CHARACTERS =================

    special_count = len(
        re.findall(r"[^a-zA-Z0-9:/._?=&%-]", url)
    )

    if special_count >= 3:

        score += 1

        reasons.append(
            "URL contains many unusual special characters."
        )

        checks.append({
            "name": "Special Character Count",
            "status": "warning",
            "message": "Many unusual characters detected."
        })

    else:

        checks.append({
            "name": "Special Character Count",
            "status": "safe",
            "message": "No excessive unusual characters detected."
        })


    # ================= RISK CLASSIFICATION =================

    # Keep score within 0-10

    score = min(score, 10)


    if score >= 5:

        status = "High Risk - Possible Phishing Website"

        risk_level = "High"


    elif score >= 2:

        status = "Medium Risk - Suspicious Website"

        risk_level = "Medium"


    else:

        status = "Low Risk - No Major Suspicious Signs"

        risk_level = "Low"


    return (
        status,
        score,
        reasons,
        risk_level,
        checks
    )


# ================= HOME =================

@app.route("/")
def home():

    conn = get_db_connection()


    total_checks = conn.execute(
        "SELECT COUNT(*) FROM checks"
    ).fetchone()[0]


    high_risk_count = conn.execute(
        "SELECT COUNT(*) FROM checks WHERE risk = 'High'"
    ).fetchone()[0]


    medium_risk_count = conn.execute(
        "SELECT COUNT(*) FROM checks WHERE risk = 'Medium'"
    ).fetchone()[0]


    low_risk_count = conn.execute(
        "SELECT COUNT(*) FROM checks WHERE risk = 'Low'"
    ).fetchone()[0]


    recent_checks = conn.execute("""
        SELECT *
        FROM checks
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()


    conn.close()


    return render_template(
        "index.html",

        total_checks=total_checks,

        high_risk_count=high_risk_count,

        medium_risk_count=medium_risk_count,

        low_risk_count=low_risk_count,

        recent_checks=recent_checks
    )


# ================= CHECK URL =================

@app.route(
    "/check",
    methods=["POST"]
)

def check_url():

    url = request.form.get(
        "url",
        ""
    ).strip()


    if not url:

        return render_template(
            "index.html",
            error="Please enter a website URL."
        )


    # Detect phishing risk

    status, score, reasons, risk_level, checks = check_phishing(url)


    # Current date/time

    checked_at = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )


    # Save to database

    conn = get_db_connection()


    conn.execute("""

        INSERT INTO checks

        (
            url,
            score,
            risk,
            status,
            reasons,
            checked_at
        )

        VALUES (?, ?, ?, ?, ?, ?)

    """, (

        url,

        score,

        risk_level,

        status,

        " | ".join(reasons),

        checked_at

    ))


    conn.commit()


    # Dashboard statistics

    total_checks = conn.execute(
        "SELECT COUNT(*) FROM checks"
    ).fetchone()[0]


    high_risk_count = conn.execute(
        "SELECT COUNT(*) FROM checks WHERE risk = 'High'"
    ).fetchone()[0]


    medium_risk_count = conn.execute(
        "SELECT COUNT(*) FROM checks WHERE risk = 'Medium'"
    ).fetchone()[0]


    low_risk_count = conn.execute(
        "SELECT COUNT(*) FROM checks WHERE risk = 'Low'"
    ).fetchone()[0]


    # Recent checks

    recent_checks = conn.execute("""

        SELECT *
        FROM checks
        ORDER BY id DESC
        LIMIT 5

    """).fetchall()


    conn.close()


    return render_template(

        "index.html",

        url=url,

        status=status,

        score=score,

        reasons=reasons,

        checks=checks,

        total_checks=total_checks,

        high_risk_count=high_risk_count,

        medium_risk_count=medium_risk_count,

        low_risk_count=low_risk_count,

        recent_checks=recent_checks

    )


# ================= HISTORY PAGE =================

@app.route("/history")

def history():

    conn = get_db_connection()


    all_checks = conn.execute("""

        SELECT *
        FROM checks
        ORDER BY id DESC

    """).fetchall()


    conn.close()


    return render_template(
        "history.html",
        checks=all_checks
    )


# ================= DELETE HISTORY =================

@app.route(
    "/clear-history",
    methods=["POST"]
)

def clear_history():

    conn = get_db_connection()


    conn.execute(
        "DELETE FROM checks"
    )


    conn.commit()

    conn.close()


    return render_template(
        "history.html",
        checks=[]
    )


# ================= START APPLICATION =================

if __name__ == "__main__":

    create_database()

    app.run(debug=True)