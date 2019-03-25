"""
LogCollector logging backend
"""

from DIRAC.FrameworkSystem.private.standardLogging.LogLevels import LogLevels
from DIRAC.Resources.LogBackends.AbstractBackend import AbstractBackend
from DIRAC.FrameworkSystem.private.standardLogging.Formatter.JsonFormatter import JsonFormatter
from DIRAC.Core.Security.Locations import getCAsLocation, getHostCertificateAndKeyLocation
from DIRAC import gLogger

import threading
import datetime
import logging
import socket
import struct
import ssl
import io
import os
import time


class LogCollectorHandler(logging.Handler, threading.Thread):
  """
  LogCollectorHandler is a custom handler for logging. It sends logging records to a LogCollector server.

  This handler requires that the formatter is the JsonFormatter.
  """

  def __init__(self, addresses, privKey, certif, caCerts) :
    """
    Initialization of the LogCollectorHandler.

    :param address : string representing one or more LogCollector server addresses obtained from the configuration.
                     Connection will always be attempted from first to last.
                     examples: "mardirac.in2p3.fr:3000,toto.in2p3.fr:1456" or "123.45.67.89:3000".

    :param privKey : string file name of the PEM encoded private key of the client.
    :param certif  : string file name of the PEM encoded certificate of the client.
    :param caCerts : string file name of the PEM encoded certificate authority list to check the server.
    """
    logging.Handler.__init__(self)
    threading.Thread.__init__(self, name="LogCollectorHandler")
    self.daemon = True
    # assign list of non-empty addresses to address
    self.addresses = addresses
    self.address = [a for a in [a.strip() for a in addresses.split(",")] if a != ""]
    self.privKey = privKey
    self.certif  = certif
    self.caCerts = caCerts
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.log = gLogger.getSubLogger('LogCollectorBackend')
    self.queueMsgs = list()
    self.queueMaxLen = 10000
    self.queueCond = threading.Condition()
    self.start()


  def emit(self, record):
    """
    Sends the record to the LogCollector server, reconnecting when required.

    The method has no effect if the connection can't be established.

    :params record: log record object
    """
    # skip log records emitted by the LogCollectorBackend to avoid endless loops
    if hasattr(record, 'customname') and record.customname.endswith('LogCollectorBackend'):
      return

    jmsg = self.format(record)
    data = io.BytesIO()
    data.write("DLCM")
    data.write(struct.pack("<I",len(jmsg)+1))
    data.write("J")
    data.write(jmsg)
    bmsg = data.getvalue()

    self.queueCond.acquire()
    self.queueMsgs.insert(0, bmsg)
    smsg = None
    if len(self.queueMsgs) > self.queueMaxLen:
      smsg = self.queueMsgs.pop().msg
    self.queueCond.notifyAll()
    self.queueCond.release()
    if smsg is not None:
      self.log.verbose("queue is full, drop message", smsg)


  def run(self):
    while (1):
      if not self.__connect():
        self.log.info("failed connecting to {}, waiting 10 seconds".format(self.addresses))
        time.sleep(10)
        continue
      while self.__send():
        pass
      self.log.info("connection closed, retry connecting to " + self.addresses)


  def __connect(self):
    """
    Connect to a LogCollector, trying addresses in sequence from first to last. Return True if succeed.

    :return: bool True if succeed, and False if failed to connect to any address in the list.
    """
    for a in self.address:
      if self.__connectTo(a):
        return True
    return False


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
      self.log.warning("open connection failed", str(e))
      return False

    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock = ssl.wrap_socket(self.sock,
        ssl_version=ssl.PROTOCOL_SSLv23,
        keyfile=self.privKey,
        certfile=self.certif,
        cert_reqs=ssl.CERT_REQUIRED, #ssl.CERT_NONE, #ssl.CERT_REQUIRED,
        ca_certs=self.caCerts,
        ciphers="ADH-AES256-SHA256:ALL")
    try:
      self.sock.connect((srvIP, int(port)))
    except Exception as e:
      self.log.debug("open connection failed", str(e))
      self.__close()
      return False
    self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    self.sock.settimeout(30)
    try:
      version = 0
      self.sock.send(bytearray([ord('D'), ord('L'), ord('C'), version]))
      resp = self.sock.recv(4)
      while len(resp) < 4:
        resp_data = self.sock.recv(4-len(resp))
        if len(resp_data) == 0:
          self.log.debug("open connection failed", "connection closed by LogCollector "+address)
          return False
        resp += resp_data
      if resp == bytearray([ord('D'), ord('L'), ord('C'), ord('S')]):
        self.log.info("connection open to " + address)
        return True
      self.log.debug("open connection failed", "invalid handshake from "+address)
    except Exception as e:
      self.log.debug("open connection failed", str(e))
      pass
    self.__close()
    return False


  def __send(self):
    """
    Try sending data and return True if succeed.

    :return: bool True if succeed, otherwise close connection and retur false.
    """
    # send message
    self.queueCond.acquire()
    while len(self.queueMsgs) == 0:
      self.queueCond.wait()
    bmsg = self.queueMsgs[-1]
    self.queueCond.release()

    try:
      self.sock.sendall(bmsg)
      self.log.debug("message sent", bmsg[8:])
    except Exception as e:
      self.log.verbose("send message failed:", str(e))
      self.__close()
      return False

    # get acknowledgement
    buf = bytearray(1)
    try:
      if self.sock.recv_into(buf) == 0:
        self.log.verbose("connection closed by peer")
        self.__close()
        return False
    except Exception as e:
      self.log.verbose("receive acknowledment failed:", str(e))
      self.__close()
      return False
    
    self.queueCond.acquire()
    if bmsg == self.queueMsgs[-1]:
      self.queueMsgs.pop()
    self.queueCond.release()
    return True

  def __close(self):
    try:
      self.sock.shutdown(socket.SHUT_RDWR)
    except:
      pass
    self.sock.close()


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
    self.__minLogLevel = None      # use global logLevel
    self.__caCertsFile = ""

  def createHandler(self, parameters=None):
    """
    Each backend can initialize its attributes and create its handler with them.

    :params parameters: dictionary of parameters. ex: {'FileName': file.log}
    """
    if parameters is not None:
      self.__LogCollectorAddress = parameters.get("LogCollectorAddress", self.__LogCollectorAddress)
      self.__minLogLevel = parameters.get('minimumLogLevel', self.__minLogLevel)
      self.__caCertsFile = parameters.get('caCertsFile', self.__caCertsFile)

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
    self._handler = LogCollectorHandler(self.__LogCollectorAddress, self.__keyFile, self.__certFile, self.__caCertsFile)
    if self.__minLogLevel is not None:
      self._handler.setLevel(LogLevels.getLevelValue(self.__minLogLevel))

  def setLevel(self, level):
    """
    Set the minimum logging level only if no minimum logLevel was specified in the configuration.

    :params level: the logging level value to set.
    """
    if self.__minLogLevel is None:
      self._handler.setLevel(level)