#!/usr/bin/env python
import sqlite3 as lite
import urllib, urllib2
import json
import sys
import os
from smtplib import SMTP_SSL as SMTP  	# this invokes the secure SMTP protocol (port 465, uses SSL)
#from smtplib import SMTP  			# use this for standard SMTP protocol   (port 25, no encryption)
# old version
# from email.MIMEText import MIMEText
from email.mime.text import MIMEText

#-------------------- CHANGE SETTINGS BELOW --------------------

db_name = "MHN_EAlert.db"

mhn_server = "http://<IP-ADDR TO YOUR MHN SERVER>"
mhn_api_key = "<YOUR MHN API KEY>"

smtp_server = '<SMTP SERVER>'
smtp_login = '<YOUR LOGIN>'
smtp_pass = '<YOUR PASSWORD>'
smtp_sender = '<YOUR SERDER E-MAIL ADDR>'
smtp_receiver = '<YOUR RECEIVER E-MAIL ADDR>'

vt_apikey = "<YOUR VIRUSTOTAL API KEY>"

# ------------------------------------------------------------

mhn_url_dionaea_capture = mhn_server + "/api/feed/?api_key="+mhn_api_key+"&channel=dionaea.capture"
mhn_md5_list = list()
db_md5_list = list()

mhn_url_glastopf_events = mhn_server + "/api/feed/?api_key="+mhn_api_key+"&channel=glastopf.events"
mhn_post_list = list()
db_post_list = list()

mhn_url_cowrie_sessions = mhn_server + "/api/feed/?api_key="+mhn_api_key+"&channel=cowrie.sessions"
mhn_command_list = list()
db_command_list = list()

# Get Detection Ratio from VirusTotal
def GetDetectionRateMD5(md5):
	try:
		url = "https://www.virustotal.com/vtapi/v2/file/report"
		parameters = {"resource": md5,"apikey": vt_apikey}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		r = urllib2.urlopen(req)
		jsondata = r.read()
		jsondict = json.loads(jsondata)

		if jsondict['response_code'] == 0:
			return str("[-]    "+jsondict['verbose_msg'])
		else:
			return str(jsondict['positives'])+"/"+str(jsondict['total'])
	except Exception, e:
	
		if "204" in str(e):
			return str("[-]    Exceed the public API request rate limit.")
		else:
			return str("[-]    " + str(e) + "\n")

# Send email
def sendmail(smtp_subject):
	# typical values for text_subtype are plain, html, xml
	text_subtype = 'plain'
	content=""

	try:
		msg = MIMEText(content, text_subtype)
		msg['Subject']	=		smtp_subject
		msg['From']   	= 		smtp_sender # some SMTP servers will do this automatically, not all

		conn = SMTP(smtp_server)
		conn.set_debuglevel(False)
		conn.login(smtp_login, smtp_pass)
		try:
			conn.sendmail(smtp_sender, smtp_receiver, msg.as_string())
		finally:
			conn.quit()

	except Exception, exc:
		sys.exit( "mail failed; %s" % str(exc) ) # give a error message
		
# Get MD5s stored in database
def get_md5s_db():
	q = "SELECT md5 FROM MHN_dionaea_capture"
	con = lite.connect(db_name)
	con.text_factory = str
	cur = con.cursor()
	cur.execute(q)
	for p in cur.fetchall():
		db_md5_list.append(p[0])

# Get HTTP POST requests stored in database
def get_posts_db():
	q = "SELECT post FROM MHN_glastopf_post"
	con = lite.connect(db_name)
	con.text_factory = str
	cur = con.cursor()
	cur.execute(q)
	for p in cur.fetchall():
		db_post_list.append(p[0])
		
# Get commands stored in database
def get_commands_db():
	q = "SELECT command FROM MHN_cowrie_commands"
	con = lite.connect(db_name)
	con.text_factory = str
	cur = con.cursor()
	cur.execute(q)
	for p in cur.fetchall():
		db_command_list.append(p[0])
		
# Add MD5 to database
def add_md5_db(md5):
	try:
		con = lite.connect(db_name)
		cur = con.cursor()
		cur.execute('INSERT INTO MHN_dionaea_capture VALUES(?)', (md5,))
		con.commit()
	except lite.Error, e:
		print "[-] Error %s:" % e.args[0]
		sys.exit(1)
	finally:
		if con:
			con.close()	
# Add HTTP POST to database
def add_post_db(post):
	try:
		con = lite.connect(db_name)
		cur = con.cursor()
		cur.execute('INSERT INTO MHN_glastopf_post VALUES(?)', (post,))
		con.commit()
	except lite.Error, e:
		print "[-] Error %s:" % e.args[0]
		sys.exit(1)
	finally:
		if con:
			con.close()	
# Add command to database
def add_command_db(command):
	try:
		con = lite.connect(db_name)
		cur = con.cursor()
		cur.execute('INSERT INTO MHN_cowrie_commands VALUES(?)', (command,))
		con.commit()
	except lite.Error, e:
		print "[-] Error %s:" % e.args[0]
		sys.exit(1)
	finally:
		if con:
			con.close()	
			
# Fetch all md5sums that dionaea have captured
def get_mhn_dionaea_captures():
	try:
		response = urllib2.urlopen(mhn_url_dionaea_capture)
		jsondata = response.read()
		jsondict = json.loads(jsondata)['data']
		for name in jsondict:
			mhn_md5_list.append(name['payload']['md5'])
	except lite.Error, e:
		print "[-] Error %s:" % e.args[0]
		sys.exit(1)
		
# Fetch all HTTP POST glastopf have captured
def get_mhn_glastopf_post():
	try:
		response = urllib2.urlopen(mhn_url_glastopf_events)
		jsondata = response.read()
		jsondict = json.loads(jsondata)['data']
		for name in jsondict:
			if "POST" in name['payload']['request_raw']:
				mhn_post_list.append(name['payload']['request_raw'])
	except lite.Error, e:
		print "[-] Error %s:" % e.args[0]
		sys.exit(1)
		
# Fetch all commands cowrie have captured
def get_mhn_cowrie_commands():
	try:
		response = urllib2.urlopen(mhn_url_cowrie_sessions)
		jsondata = response.read()
		jsondict = json.loads(jsondata)['data']
		for name in jsondict:
			if name['payload']['commands']:
				for commands in name['payload']['commands']:
					mhn_command_list.append(commands)
			if name['payload']['unknownCommands']:
				for unknownCommands in name['payload']['unknownCommands']:
					mhn_command_list.append(unknownCommands)
				
	except lite.Error, e:
		print "[-] Error %s:" % e.args[0]
		sys.exit(1)
			
# Create database with tables
def db_create():
    con = None
    try:
		con = lite.connect(db_name)
		cur = con.cursor()
		cur.execute('CREATE TABLE MHN_dionaea_capture(md5 TEXT)')
		cur.execute('CREATE TABLE MHN_glastopf_post(post TEXT)')
		cur.execute('CREATE TABLE MHN_cowrie_commands(command TEXT)')
    except lite.Error, e:
        print "[-] Error %s:" % e.args[0]
        sys.exit(1)
    finally:
        if con:
            con.close()

# check if md5 exist within db
# if not, add to database and alert via email
def get_and_check_md5():
	get_mhn_dionaea_captures()
	get_md5s_db()
	
	for mhn_md5 in mhn_md5_list:
		if mhn_md5 not in db_md5_list:
			add_md5_db(mhn_md5)
			get_md5s_db()
			smtp_subject = "[MHN] New Dionaea Capture: " + mhn_md5 + " " + GetDetectionRateMD5(mhn_md5)
			sendmail(smtp_subject)

# check if post exist within db
# if not, add to database and alert via email
def get_and_check_post():
	get_mhn_glastopf_post()
	get_posts_db()
	
	for mhn_post in mhn_post_list:
		if mhn_post not in db_post_list:
			add_post_db(mhn_post)
			get_posts_db()
			smtp_subject = "[MHN] New HTTP POST to Glastopf: " + mhn_post
			sendmail(smtp_subject)
			
# check if commands exist within db
# if not, add to database and alert via email
def get_and_check_command():
	get_mhn_cowrie_commands()
	get_commands_db()
	
	for mhn_command in mhn_command_list:
		if mhn_command not in db_command_list:
			add_command_db(mhn_command)
			get_commands_db()
			smtp_subject = "[MHN] New Command to Cowrie: " + mhn_command
			sendmail(smtp_subject)
			
if __name__ == '__main__':
	# Check if db exist
	if os.path.isfile(db_name):
		get_and_check_md5()
		get_and_check_post()
		get_and_check_command()
	else:
		db_create()
		get_and_check_md5()
		get_and_check_post()
		get_and_check_command()
