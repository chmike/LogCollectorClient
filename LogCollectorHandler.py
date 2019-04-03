"""
LogCollector handler
"""

# This file is for testing the LogCollectorHandler outside of Dirac.
# When modified make sure the class is identical to the LogCollectonHandler
# class in LogCollectorBackend.py which is the file used in Dirac.
# The main program for testing is LogCollectorClient.py.

from LogCollectorLogger import gLogger

import threading
import datetime
import logging
import socket
import select
import struct
import time
import ssl
import io


class LogCollectorHandler(logging.Handler, threading.Thread):
  """
  LogCollectorHandler is a custom handler for logging. It sends logging records to a LogCollector server.

  This handler requires that the formatter is the JsonFormatter.
  """

  def __init__(self, addresses, privKey, certif, caCerts) :
    """
    Initialization of the LogCollectorHandler.

    :param addresses : list of LoqCollector addresses of the form "<host>:<port>".
                       Connection will always be attempted from first to last.
                       examples: "mardirac.in2p3.fr:3000" or "123.45.67.89:3000".
    :param privKey   : string file name of the PEM encoded private key of the client.
    :param certif    : string file name of the PEM encoded certificate of the client.
    :param caCerts   : string file name of the PEM encoded certificate authority list to check the server.
    """
    logging.Handler.__init__(self)
    threading.Thread.__init__(self, name="LogCollectorHandler")
    self.addrList = [a for a in [a.strip() for a in addresses.split(",")] if a != ""]
    self.addresses = addresses
    self.privKey = privKey
    self.certif  = certif
    self.caCerts = caCerts
    #self.log = gLogger.getSubLogger('LogCollectorBackend')
    self.sock = None
    self.msgQueue = list()  # json encoded messages to send
    self.msgToAck = list()  # json encoded messages waiting acknowledgement
    self.maxNbrMsg = 10000  # max number of messages in queue + toAck
    self.queueCond = threading.Condition()
    self.packet = io.BytesIO()
    self.maxPktLen = 1500
    self.buf = bytearray(1)
    self.daemon = True
    self.start()


  def emit(self, record):
    """
    Queue the record for asynchronous sending to the LogCollector.

    The oldest logging message in the queue is dropped when the queue ovorflows.

    :params record: log record object
    """
    # skip log records emitted by the LogCollectorBackend to avoid endless loops
    #if hasattr(record, 'customname') and record.customname.endswith('LogCollectorBackend'):
    #  return

    self.queueCond.acquire()
    self.msgQueue.insert(0, self.format(record))
    if len(self.msgQueue) + len(self.msgToAck) > self.maxNbrMsg:
      jmsg = self.msgQueue.pop()
      print "queue is full, drop message: "+jmsg
      #self.log.verbose("queue is full, drop message: "+jmsg)
    #print "emit: queue len:", len(self.msgQueue), "toAck len:", len(self.msgToAck)
    self.queueCond.notifyAll()
    self.queueCond.release()


  def run(self):
    while (1):
      self.queueCond.acquire()
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
          print "connection closed by logCollector (exceptional)"
          self.__resetConnection()
          continue

        if readable:
          try:
            acks = self.sock.read()
            if not acks:
              print "connection closed by logCollector (read 0)"
              #self.log.verbose("connection closed by logCollector")
              self.__resetConnection()
              continue
          except Exception as e:
            print "read acknowledgments failed:" + str(e)
            #self.log.verbose("read acknowledgments failed:" + str(e))
            self.__resetConnection()
            continue
          for a in acks:
            self.msgToAck.pop()
          #print "read: queue len:", len(self.msgQueue), "toAck len:", len(self.msgToAck), "acks len:", len(acks)

        if writable:
          try:
            #print "send: queue len:", len(self.msgQueue), "toAck len:", len(self.msgToAck)
            self.sock.sendall(self.packet.getvalue())
            self.__clearPacket()
          except Exception as e:
            print "send message failed:" + str(e)
            #self.log.verbose("send message failed:" + str(e))
            self.__resetConnection()
            continue

      
  def __connect(self):
    """
    Connect to a LogCollector, trying addresses in sequence from first to last.
    If failed, wait 10 seconds, and retry. 
    requires queueCond is NOT acquired to avoid deadlock. 
    """
    while 1:
      for a in self.addrList:
        print "try connecting to", a
        if self.__connectTo(a):
          return
      print "failed connecting to {}, waiting 10 seconds".format(self.addresses)
      #self.log.info("failed connecting to {}, waiting 10 seconds".format(self.addresses))
      time.sleep(10)
 

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
      print "open connection failed:", str(e)
      #self.log.warning("open connection failed", str(e))
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
      print "open connection failed:", str(e)
      #self.log.debug("open connection failed", str(e))
      self.__close()
      return False
    self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    self.sock.settimeout(30)
    try:
      version = 0
      self.sock.send(bytearray('DLC\x00')) # protocol version 0
      resp = self.sock.recv(4)
      while len(resp) < 4:
        resp_data = self.sock.recv(4-len(resp))
        if len(resp_data) == 0:
          print "open connection failed:", "connection closed by LogCollector "+address
          #self.log.debug()
          return False
        resp += resp_data
      if resp == bytearray('DLCS'):
        print "connection open to " + address
        #self.log.info("connection open to " + address)
        return True
      #self.log.debug("open connection failed", "invalid handshake from "+address)
    except Exception as e:
      print "open connection failed:", str(e)
      #self.log.debug("open connection failed", str(e))
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
      jMsg = self.msgQueue[-1]
      self.packet.write('DLCM')
      self.packet.write(struct.pack('<I',len(jMsg)+1))
      self.packet.write('J')
      self.packet.write(jMsg)
      self.msgToAck.insert(0, jMsg)
      self.msgQueue.pop()
      #print "pack: queue len:", len(self.msgQueue), "toAck len:", len(self.msgToAck)
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
    self.msgToAck = list()
    #print "reset: queue len:", len(self.msgQueue), "toAck len:", len(self.msgToAck)
    self.__close()


  def __close(self):
    if self.sock != None:
      try:
        self.sock.shutdown(socket.SHUT_RDWR)
      except:
        pass
      self.sock.close()
      self.sock = None


