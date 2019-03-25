import logging
from pythonjsonlogger import jsonlogger
from datetime import datetime


class Logger(object):
  DEBUG = logging.DEBUG
  VERBOSE = 15
  INFO = logging.INFO
  WARN = logging.WARN
  NOTICE = 35
  ERROR = logging.ERROR
  ALWAYS = 45
  FATAL = logging.CRITICAL

  def __init__(self, subLogger=''):
    self._subLogger = subLogger
    self.levelStr = {
      self.DEBUG:   "DEBG",
      self.VERBOSE: "VERB",
      self.INFO:    "INFO",
      self.WARN:    "WARN",
      self.ERROR:   "ERRO",
      self.FATAL:   "FATL"
    }
    self._log = logging.getLogger('py-dmon')
    self._log.setLevel(Logger.DEBUG)
    # stdOutHandler = logging.StreamHandler()
    # stdOutHandler.setFormatter(jsonlogger.JsonFormatter("%(asctime)s UTC %(name)s %(levelname)s: %(message)", "%Y-%m-%d %H:%M:%S"))
    # self._log.addHandler(stdOutHandler)

  def addHandler(self, handler, logLevel):
    handler.setLevel(logLevel)
    handler.setFormatter(jsonlogger.JsonFormatter("%(asctime)s UTC %(name)s %(levelname)s: %(message)", "%Y-%m-%d %H:%M:%S"))
    self._log.addHandler(handler)

  def getSubLogger(self, subLogger):
    return Logger(subLogger)

  def debug(self, sMsg, sVarMsg=''):
    return self._createLogRecord(Logger.DEBUG, sMsg, sVarMsg)

  def verbose(self, sMsg, sVarMsg=''):
    return self._createLogRecord(Logger.VERBOSE, sMsg, sVarMsg)

  def info(self, sMsg, sVarMsg=''):
    return self._createLogRecord(Logger.INFO, sMsg, sVarMsg)

  def warning(self, sMsg, sVarMsg=''):
    return self._createLogRecord(Logger.WARN, sMsg, sVarMsg)
 
  def notice(self, sMsg, sVarMsg=''):
    return self._createLogRecord(Logger.NOTICE, sMsg, sVarMsg)

  def error(self, sMsg, sVarMsg=''):
    return self._createLogRecord(Logger.ERROR, sMsg, sVarMsg)

  def fatal(self, sMsg, sVarMsg=''):
    return self._createLogRecord(Logger.FATAL, sMsg, sVarMsg)

  def _createLogRecord(self, level, sMsg, sVarMsg, exc_info=False):
    #print datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.levelStr[level], sMsg, sVarMsg

    extra = {'componentname': self._subLogger,
              'varmessage': sVarMsg,
              'spacer': '' if not sVarMsg else ' ',
              'customname': self._subLogger}
    self._log.log(level, "%s", sMsg, exc_info=exc_info, extra=extra)
    return self._log.level <= level



gLogger = Logger()
