# reconscript
Automated Recon &amp; Reporting Script

Edit your script file to fill in the domain or website you want to target.

What This Script Does:

 -  Gathers WHOIS, DNS, HTTP headers, cookies.

 -   Looks for exposed sensitive files and directories.

 -   Downloads JS and extracts endpoints/secrets.

 -   Performs fast XSS/SQLi probes and directory brute-forcing.

 -   Scans for common web vulnerabilities with Nikto and Nuclei.

 -   Auto-generates a summary report (report.txt) combining the key findings from each tool.

How to Use:

    Make executable:
    chmod +x recon_automate.sh

    Run:
    ./recon_automate.sh

    All your results, logs, and report.txt summary will be in a timestamped output folder.
