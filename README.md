MHNCaptureEAlert
============

This script will send an e-mail alert when your MHN (Modern Honey Network) server capture new data

Tips: Set this script to run as a cron job

#Notifications:
- Dionaea capture new file -> Send e-mail with MD5 and VirusTotal detection ratio
- Glastopf event with HTTP POST request -> Send e-mail with the HTTP POST Request
- Cowrie session with command -> Send e-mail with the command


#Requirements:
- A Modern Honey Network (MHN) server. Read more at https://github.com/threatstream/mhn/
- Python
