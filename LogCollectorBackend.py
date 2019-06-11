"""
LogCollector logging backend
"""

# The LogCollectorHandler class must be an exact copy of the LogCollectorHandler class
# in LogCollectorHandler.py file that has been tested with LogCollectorClient.py.
# Requires that python-json-logger is installed:
#     $ pip2 install python-json-logger

from DIRAC.FrameworkSystem.private.standardLogging.LogLevels import LogLevels
from DIRAC.Resources.LogBackends.AbstractBackend import AbstractBackend
from DIRAC.FrameworkSystem.private.standardLogging.Formatter.JsonFormatter import JsonFormatter
from DIRAC.Core.Security.Locations import getCAsLocation, getHostCertificateAndKeyLocation
from DIRAC import gLogger

from collections import deque

import threading
import datetime
import logging
import socket
import select
import struct
import time
import ssl
import sys
import io
import os
import re


class LogCollectorHandler(logging.Handler, threading.Thread):
  """
  LogCollectorHandler is a custom handler for logging. It sends logging records to a LogCollector server.

  This handler requires that the formatter is the JsonFormatter.
  """

  def __init__(self, addresses, privKey, certif, caCerts, minLevel, name) :
    """
    Initialization of the LogCollectorHandler.

    :param addresses : list of LoqCollector addresses of the form "<host>:<port>".
                       Connection will always be attempted from first to last.
                       examples: "toto.example.com:3000" or "123.45.67.89:3000".
    :param privKey   : string file name of the PEM encoded private key of the client.
    :param certif    : string file name of the PEM encoded certificate of the client.
    :param caCerts   : string file name of the PEM encoded certificate authority list to check the server.
    :param minLevel  : integer number of minimum log level accepted by this handler. 
    :param name      : string client name to pass in connection init.
    """
    logging.Handler.__init__(self)
    threading.Thread.__init__(self, name="LogCollectorHandler")
    self.addrList = [a for a in [a.strip() for a in addresses.split(",")] if a != ""]
    self.addresses = addresses
    self.privKey = privKey
    self.certif  = certif
    self.caCerts = caCerts
    self.minLevel = minLevel
    self.level = minLevel
    self.name = name
    self.log = gLogger.getSubLogger('LogCollectorBackend')
    self.sock = None
    self.msgQueue = deque()  # json encoded messages to send
    self.msgToAck = deque()  # json encoded messages waiting acknowledgement
    self.maxNbrMsg = 10000  # max number of messages in queue + toAck
    self.queueCond = threading.Condition()
    self.packet = io.BytesIO()
    self.maxPktLen = 1500
    self.buf = bytearray(1)
    self.daemon = True
    self.start()


  def setLevel(self, level):
    """
    Set the logging level of this handler, but not below self.minLevel.
    """
    self.level = level if level > self.minLevel else self.minLevel


  def emit(self, record):
    """
    Queue the record for asynchronous sending to the LogCollector.

    The oldest logging message in the queue is dropped when the queue overflows.

    :params record: log record object
    """
    # skip log records emitted by the LogCollectorBackend to avoid endless loops
    if hasattr(record, 'customname') and record.customname.endswith('LogCollectorBackend'):
      return
    self.queueCond.acquire()
    self.msgQueue.appendleft(self.format(record))
    if len(self.msgQueue) + len(self.msgToAck) > self.maxNbrMsg:
      jmsg = self.msgQueue.pop()
      self.queueCond.release()
      self.log.verbose("queue is full, drop message: "+jmsg)
      self.queueCond.acquire()
    self.queueCond.notifyAll()
    self.queueCond.release()


  def run(self):
    self.log.info("start LogCollector thread")
    self.queueCond.acquire()
    while (1):
      while len(self.msgQueue) == 0:
        self.queueCond.wait(5)  # TODO: check if the 5 sec timeout is needed
 
      while len(self.msgQueue) > 0 or len(self.msgToAck) > 0:
        if self.sock == None:
          self.queueCond.release()
          self.__connect()  # returns when connected
          self.queueCond.acquire()
        
        input = [self.sock]
        output = []
        if self.__fillPacketToSend():
          output = [self.sock]
        self.queueCond.release()
        readable, writable, exceptional = select.select(input, output, input, 5) # TODO wait forever or tmo ?
        self.queueCond.acquire()

        if exceptional:
          self.queueCond.release()
          self.log.verbose("connection closed by logCollector (exceptional)")
          self.queueCond.acquire()
          self.__resetConnection()
          continue

        if readable:
          try:
            acks = self.sock.read()
            if not acks:
              self.queueCond.release()
              self.log.verbose("connection closed by logCollector (read 0)")
              self.queueCond.acquire()
              self.__resetConnection()
              continue
          except Exception as e:
            self.queueCond.release()
            self.log.verbose("read acknowledgments failed:" + str(e))
            self.queueCond.acquire()
            self.__resetConnection()
            continue
          for _ in acks:
            self.msgToAck.pop()

        if writable:
          try:
            self.sock.sendall(self.packet.getvalue())
            self.__clearPacket()
          except Exception as e:
            self.queueCond.release()
            self.log.verbose("send packet of messages failed:" + str(e))
            self.queueCond.acquire()
            self.__resetConnection()
            continue

      
  def __connect(self):
    """
    Connect to a LogCollector, trying addresses in sequence from first to last.
    If failed, wait 10 seconds, and retry. 
    requires queueCond is NOT acquired to avoid deadlock. 
    """
    while 1:
      for address in self.addrList:
        self.log.info("try connecting to", address)
        if self.__connectTo(address):
          self.log.info("connection open to " + address)
          return
      self.log.info("failed connecting to {}, waiting 15 seconds".format(self.addresses))
      time.sleep(15)
 

  def __connectTo(self, address):
    """
    Try connecting to the LogCollector at the given address.

    :return: bool True if succeed, and False otherwise.
    """
    try:
      srvName, port = address.split(":")
      # resolve again in case the IP addresss of srvName changed
      srvIP = socket.gethostbyname(srvName)
    except Exception as e:
      self.log.verbose("open connection failed:", str(e))
      return False

    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock = ssl.wrap_socket(self.sock,
        ssl_version=ssl.PROTOCOL_SSLv23,
        keyfile=self.privKey,
        certfile=self.certif,
        cert_reqs=ssl.CERT_NONE, #ssl.CERT_NONE, #ssl.CERT_REQUIRED,
        ca_certs=self.caCerts,
        ciphers="ADH-AES256-SHA256:ALL")
    try:
      self.sock.connect((srvIP, int(port)))
    except Exception as e:
      self.log.verbose("open connection failed:", str(e))
      self.__close()
      return False
    self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    self.sock.settimeout(30)
    try:
      name = bytearray(self.name, 'utf-8')
      initMsg = io.BytesIO()
      initMsg.write(struct.pack('<I',len(name)))
      initMsg.write(name)
      self.sock.send(bytearray('DLC\x01')) # protocol version 1
      self.sock.sendall(initMsg.getvalue())
      resp = self.sock.recv(4)
      while len(resp) < 4:
        resp_data = self.sock.recv(4-len(resp))
        if len(resp_data) == 0:
          self.log.verbose("open connection failed:", "connection closed by logCollector "+address)
          return False
        resp += resp_data
      if resp == bytearray('DLCS'):
        return True
      self.log.debug("open connection failed", "invalid handshake from "+address)
    except Exception as e:
      self.log.verbose("open connection failed", str(e))
      pass
    self.__close()
    return False


  def __fillPacketToSend(self):
    """
    Fill packet to send. Requires queueCond is acquired.

    :return: bool True if there is data to send in the packet. 
    """
    if len(self.msgQueue) == 0:
      return self.packet.tell() != 0
    while len(self.msgQueue) > 0 and self.maxPktLen - self.packet.tell() >= 7 + len(self.msgQueue[-1]):
      jMsg = self.msgQueue.pop()
      self.packet.write('DLCM')
      self.packet.write(struct.pack('<I',len(jMsg)+1))
      self.packet.write('J')
      self.packet.write(jMsg)
      self.msgToAck.appendleft(jMsg)
    return True
  

  def __clearPacket(self):
    self.packet.truncate(0)
    self.packet.seek(0,0)


  def __resetConnection(self):
    """
    Append msgToAck messages to msgQueue, and close socket.
    Requires queueCond is acquired.
    """
    self.msgQueue.extend(self.msgToAck)
    self.msgToAck = deque()
    self.__clearPacket()
    self.__close()


  def __close(self):
    if self.sock != None:
      try:
        self.sock.shutdown(socket.SHUT_RDWR)
      except:
        pass
      self.sock.close()
      self.sock = None



class LogCollectorBackend(AbstractBackend):
  """
  LogCollectorBackend is used to create an abstraction of the handler and the formatter concepts from logging.
  Here, we have:

    - LogCollectorHandler: which is a custom handler created in DIRAC to send log records to a LogCollector server.
    - JsonFormatter: is a custom Formatter object, created for DIRAC in order to get json encoded log records.
                     You can find it in FrameworkSystem/private/standardLogging/Formatter
  """
  def __init__(self):
    """
    Initialization of the MessageQueueBackend
    """
    super(LogCollectorBackend, self).__init__(None, JsonFormatter)
    self.__LogCollectorAddress = 'localhost:3000'
    self.__minLevel = 0
    self.__caCertsFile = ""
    self.__name = "LogCollectorBackend"
    # get positional command line arguments
    posArgs = []
    for arg in sys.argv:
      if len(arg) > 0 and arg[0] != '-':
        posArgs.append(arg)
    print sys.argv
    print posArgs
    # get process type and name from command line arguments
    if len(posArgs) >= 2:
        p = re.compile("dirac-([a-zA-Z0-9]+).py")
        m = p.search(posArgs[0])
        if m is None:
          self.__name = "???:"+posArgs[1]
        else:
          self.__name = m.group(1)+":"+posArgs[1]

  def createHandler(self, parameters=None):
    """
    Each backend can initialize its attributes and create its handler with them.

    :params parameters: dictionary of parameters. ex: {'FileName': file.log}
    """
    if parameters is not None:
      self.__LogCollectorAddress = parameters.get("LogCollectorAddress", self.__LogCollectorAddress)
      self.__caCertsFile = parameters.get('caCertsFile', self.__caCertsFile)
      try:
        self.__minLevel = LogLevels.getLevelValue(parameters.get('minimumLogLevel', "INFO"))
      except:
        pass

    self.__LogCollectorAddress = ','.join([a for a in [a.strip() for a in self.__LogCollectorAddress.split(",")] if a != ""])

    if self.__caCertsFile == "":
      self.__caCertsFile = getCAsLocation()
      if self.__caCertsFile == False:
        gLogger.error("can't locate the CA certs directory")
        return
      self.__caCertsFile += "/cas.pem"
    if not os.path.isfile(self.__caCertsFile):
        gLogger.error("caCertsFile '"+self.__caCertsFile+"' doesn't exist or is not a regular file")
        return

    self.__certKeyFiles = getHostCertificateAndKeyLocation()
    if self.__certKeyFiles == False:
      gLogger.error("can't locate the host certificate and private key files")
      return
    self.__certFile = self.__certKeyFiles[0]
    self.__keyFile = self.__certKeyFiles[1]
    self._handler = LogCollectorHandler(
      self.__LogCollectorAddress, 
      self.__keyFile, 
      self.__certFile, 
      self.__caCertsFile, 
      self.__minLevel,
      self.__name)

  def setLevel(self, level):
    """
    Set the log level of the LogCollector handler. 

    :params level: integer the logging level value to set.
    """
    self._handler.setLevel(level)
