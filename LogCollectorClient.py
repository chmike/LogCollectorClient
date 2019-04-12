#!/usr/bin/env python2

from LogCollectorHandler import LogCollectorHandler
from LogCollectorLogger import gLogger, Logger
from datetime import datetime
import traceback
import argparse
import logging
import time
import sys



if __name__ == '__main__': 
  parser = argparse.ArgumentParser(description='LogCollector client')
  parser.add_argument('-a', dest='addresses', action='store', default="127.0.0.1:3000",
                  help='list of LogCollector address (default "127.0.0.1:3000")')
  parser.add_argument('-n', dest='nbrLoops', type=int, action='store', default=0,
                  help='number of loops, 0 = forever (default 0)')
  parser.add_argument('-fast', dest='fast', action='store_true',
                  help='send messages at full speed')
  args = parser.parse_args()
  print "args:", args

  args.addresses = ','.join([a for a in [a.strip() for a in args.addresses.split(",")] if a != ""])

  try:
    lch = LogCollectorHandler(args.addresses, "pki/key.pem", "pki/crt.pem", "pki/cas.pem")
    gLogger.addHandler(lch, Logger.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    #gLogger.addHandler(handler, logging.DEBUG)
    
    i = 0
    while (args.nbrLoops == 0 or i < args.nbrLoops):
      i += 1
      gLogger.info('no problem 1')
      gLogger.info('no problem 2')
      gLogger.info('no problem 3')
      gLogger.info('no problem 4')
      gLogger.info('no problem 5')
      if not args.fast:
        time.sleep(1)

  except KeyboardInterrupt:
    print "Shutdown requested...exiting"
  except Exception:
    traceback.print_exc(file=sys.stderr)
  except:
    print "Unexpected error:", sys.exc_info()
    print traceback.format_exc()

  sys.exit(0)