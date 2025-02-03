## Overview
This Web Application Firewall (WAF) is designed to protect web applications from common cyber threats such as:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Bad Bots and Automated Scanners
- Rate Limiting to prevent DoS attacks

The WAF is implemented in Python using the Flask framework and provides a simple UI for interaction.

---

## Features
### 🔒 **Security Protections**
1. **SQL Injection Detection** – Blocks malicious queries attempting to manipulate databases.
2. **XSS Prevention** – Detects and blocks JavaScript injection attacks.
3. **User-Agent Filtering** – Blocks known bad bots such as `sqlmap`, `nmap`, and `curl`.
4. **Rate Limiting** – Restricts excessive requests from the same IP to prevent DoS attacks.
5. **IP Blocking** – Permanently blocks an IP if an SQL injection attempt is detected.
6. **Logging System** – Logs attack attempts in `waf_logs.json` for analysis.
7. **Dynamic UI** – Friendly error pages and a structured homepage.

---

## Installation & Setup
### **1️⃣ Prerequisites**
Ensure you have **Python 3** installed along with the necessary dependencies.

### **2️⃣ Install Required Dependencies**
Run the following command to install Flask:
```bash
pip install flask
```

### **3️⃣ Clone the Repository**
```bash
git clone https://github.com/yourusername/WAF_Project.git
cd WAF_Project
```

### **4️⃣ Run the Application**
```bash
python waf.py
```

The application will start on **http://127.0.0.1:5000/**.

---

## How to Use
- **Normal Users:** Navigate to the homepage and interact with the site.
- **Testing Security:** Try injecting malicious queries into URL parameters or form fields to trigger the WAF protection.
- **Viewing Logs:** Check `waf_logs.json` for detected attacks.

## Conclusion
This WAF enhances web security by protecting against SQL Injection, XSS, and bot attacks. It also provides useful logs for further security analysis. Feel free to improve and extend it based on your needs.

🚀 **Future Improvements:**
- Implement JWT authentication
- Add machine learning-based anomaly detection
- Deploy on a cloud server for real-world usage

For any questions, contact or raise an issue on GitHub!

**Happy Securing!** 🔐

