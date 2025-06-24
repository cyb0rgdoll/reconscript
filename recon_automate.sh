#!/bin/bash

# Set your target
TARGET="https://domain.com"
TARGET_DOMAIN="domain.org"
DATE=$(date +"%Y-%m-%d_%H-%M")
OUTPUT_DIR="domain-recon-$DATE"
mkdir "$OUTPUT_DIR" && cd "$OUTPUT_DIR"

# 1. Basic recon
echo "[*] WHOIS and DNS info" | tee -a recon.txt
whois $TARGET_DOMAIN | grep -Ei 'Domain|Registrar|Expiry' >> recon.txt
dig $TARGET_DOMAIN ANY +short >> recon.txt

# 2. Header and cookie checks
echo "[*] HTTP headers:" | tee -a recon.txt
curl -I $TARGET | tee headers.txt >> recon.txt

echo "[*] Set-Cookie headers:" | tee -a recon.txt
curl -I $TARGET | grep -i set-cookie | tee cookies.txt >> recon.txt

# 3. Security header analysis
echo "[*] Checking security headers:" | tee -a recon.txt
curl -I $TARGET | grep -Ei 'x-frame-options|strict-transport-security|x-content-type-options|content-security-policy|referrer-policy|permissions-policy' | tee sec-headers.txt >> recon.txt

# 4. Directory brute force (common sensitive files)
echo "[*] Directory brute force (top 1000 words):" | tee -a recon.txt
gobuster dir -u $TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt,html,bak,zip --exclude-length 15 | tee gobuster.txt >> recon.txt

# 5. Look for backup/config files
echo "[*] Checking for common sensitive files:" | tee -a recon.txt
for f in .env config.php backup.sql wp-config.php .git .svn; do
  code=$(curl -s -o /dev/null -w "%{http_code}" $TARGET/$f)
  echo "$f: $code" | tee -a files.txt
done

# 6. Download and analyze JS for endpoints and secrets
echo "[*] Downloading and analyzing JS files..."
mkdir jsfiles && cd jsfiles
wget -r -l2 -A.js $TARGET
grep -Eo 'https?://[^"]+' $(find . -name '*.js') | sort -u > ../js_urls.txt
grep -iE 'api[_-]?key|secret|token|password' $(find . -name '*.js') > ../js_secrets.txt
cd ..
echo "[*] JS endpoints and secrets extracted." | tee -a recon.txt

# 7. Quick XSS/SQLi/IDOR payload test templates
echo "[*] XSS test on search (if exists):" | tee -a recon.txt
curl "$TARGET/search?q=<script>alert(1)</script>" | grep -i script >> xss-test.txt

echo "[*] SQLi test on example param (manual review needed):" | tee -a recon.txt
curl "$TARGET/page.php?id=1%20OR%201=1" >> sqli-test.txt

echo "[*] IDOR manual test: (change ID in URL if found, manual follow-up required)" | tee -a recon.txt

# 8. Nikto scan for misconfigs
echo "[*] Nikto scan:" | tee -a recon.txt
nikto -h $TARGET | tee nikto.txt >> recon.txt

# 9. Nuclei scan for CVEs and known issues (optional - can be slow)
echo "[*] Nuclei scan:" | tee -a recon.txt
nuclei -u $TARGET -t cves/ | tee nuclei.txt >> recon.txt

# 10. Summary report
echo "[*] Automated Recon Complete."
echo -e "\nSummary of findings saved in $OUTPUT_DIR."
echo -e "\n--- Sample Report ---"
echo "Recon and security scan for: $TARGET ($DATE)" > report.txt
echo -e "\nWHOIS & DNS info:\n" >> report.txt
cat recon.txt >> report.txt
echo -e "\nFound directories/files:\n" >> report.txt
cat gobuster.txt >> report.txt
echo -e "\nExposed cookies:\n" >> report.txt
cat cookies.txt >> report.txt
echo -e "\nMissing/misconfigured security headers:\n" >> report.txt
cat sec-headers.txt >> report.txt
echo -e "\nPotential endpoints from JS:\n" >> report.txt
cat js_urls.txt >> report.txt
echo -e "\nPotential secrets in JS:\n" >> report.txt
cat js_secrets.txt >> report.txt
echo -e "\nNikto findings:\n" >> report.txt
cat nikto.txt >> report.txt
echo -e "\nNuclei findings:\n" >> report.txt
cat nuclei.txt >> report.txt

echo -e "\n--- End of Automated Report ---\n"
