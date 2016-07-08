#!/usr/bin/python

import sys, getopt
import sqlite3
import requests, json

contacts_file = ''   # contact file (fo analyze mode)
leaks_file = ''      # plain text leak file (when initializing the DB)
mode = ''            # 2 modes possible: "init" or "analyze"
modules = ''         # modules to use when in analyze mode (currently only '' or 'adobe')

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def error(err):
  print 'leakAnalyzer.py [-h] --mode=<command> [--contacts=<filename>] [--leak=<filename>] [--db]'
  print 'where <command> is one of "init" or "analyze"'
  sys.exit(err)


# Initialize a sqlite DB of the leaks
def init(conn, cur):
  global leak_file

  # Initialize sqlite DB
  print bcolors.HEADER + "Initialzing sqlite leaks DB..." + bcolors.ENDC
  c.execute('PRAGMA cache_size = -1024000') # 1GB
  c.execute('PRAGMA journal_mode = OFF')
  c.execute('CREATE TABLE emails (email text, pwd text)')
  c.execute('CREATE TABLE hashes (pwd text, use int, hints text)')
  

  # Digest Adobe leak DB for faster lookups
  print bcolors.HEADER + "Digesting leak file into sqlite leaks DB..." + bcolors.ENDC
  counter = 1
  pwd = {}
  with open(leaks_file) as f:
    for l in f:

      # Output status
      print "Processing line " + str(counter) + '\r',
      counter += 1

      # Skip empty lines
      if not l.strip(): 
        continue

      # We don't need the 4 last characters; They are always equal to "|--\n"
      l = l[:-4]

      # Digest useful emails info   
      try: 

        # Extract info
        email = l.split('-|-')[2]
        pwd_hash = l.split('-|-')[3]
        pwd_hint = l.split('-|-')[4]
      except:
        continue
      
      # Insert email infos into DB
      info = [ email, pwd_hash ]
      cur.execute('INSERT INTO emails VALUES (?, ?)', info) 
  
      # Keep track of password info for later insertion in DB
      if not pwd.get(pwd_hash):
        pwd[pwd_hash] = { 'Use' : 1, 'Hints' : [pwd_hint] }
      else:
        pwd[pwd_hash]['Use'] += 1
        if pwd_hint:
          pwd[pwd_hash]['Hints'].append(pwd_hint)
 
  # Update hashes table
  print ''
  print bcolors.HEADER + 'Digesting password informations...' + bcolors.ENDC
  for p,info in pwd.items():
    row = [ p, info['Use'], ','.join(info['Hints']) ]
    cur.execute('INSERT INTO hashes VALUES (?, ?, ?)', row)

  # Commit changes
  conn.commit()
  print bcolors.HEADER + "Done initializing sqlite leak DB..." + bcolors.ENDC


def analyze(cur):
  global contacts_file, modules

  # Parse contacts list and find out which email address was leaked
  print bcolors.HEADER + "Looking up haveibeenpwned.com for leaks for the provided email addresses" + bcolors.ENDC
  with open(contacts_file) as f:
    for l in f:

      # Get email address
      email = l.rstrip('\n')
      print bcolors.BOLD + "Looking up " + email + "..." + bcolors.ENDC

      # Ask haveibeenpwned.com domain 
      url = 'https://haveibeenpwned.com/api/v2/breachedaccount/' + email + '?truncateResponse=true'
      resp = requests.get(url, verify=False)

      # Analyze results
      leaks= []
      if resp.status_code == 200: 
         
        # Found a leak?
        leaks = json.loads(resp.content)
	print bcolors.FAIL + "Found leaks for " + email + " : " + str(leaks) + bcolors.ENDC

        # Analyze email addresses against leaks db if requested
        if "adobe" in modules:
          for leak in leaks:
            if leak['Name'] == 'Adobe':
              analyze_adobe_leak(email, cur)


def analyze_adobe_leak(email, cur):

  # lookup emails in adobe leak
  print bcolors.HEADER + "Looking up for additional info in the adobe leak..." + bcolors.ENDC
  cur.execute('SELECT pwd FROM emails WHERE email=? LIMIT 1', [email] ) 
  pwd = cur.fetchone()
  cur.execute('SELECT use, hints FROM hashes WHERE pwd=? LIMIT 1', pwd ) 
  r = cur.fetchone()
  print email + ' uses a password used by ' + str( r[0]-1 ) + ' other user(s).'
  if r[1]:
    print 'collected password hints are: ' + r[1]


def main(argv):
  global contacts_file, leaks_file, mode, modules
  
  # process arguments
  try:
    opts, args = getopt.getopt(argv, 'h:', ['contacts=','leak_file=', 'mode=', 'modules='])
  except getopt.GetoptError:
    error(2)
  for opt, arg in opts:
    # print help
    if opt == '-h':
      error(1)
    # mode
    elif opt == '--mode':
      mode = arg
    # plain text leak file
    elif opt == '--leak_file':
      leaks_file = arg
    # contacts file
    elif opt == '--contacts':
      contacts_file = arg
    # db
    elif opt == '--modules':
      modules = arg
  
  # Open leaks sqlite DB
  conn = sqlite3.connect('./leaks.db')
  cur = conn.cursor()

  # Run requested mode
  if mode == 'init':
    if leaks_file:
      init(conn, cur)
    else:
      print 'The "leak_file" argument is mandatory in "init" mode'
      error(2)
  elif mode == 'analyze':
    if contacts_file:
      analyze(cur)
    else:
      print 'The "contacts" argument is mandatory in "analyze" mode'
      error(2)
  else:
    error(2)


if __name__ == "__main__":
  main(sys.argv[1:])
