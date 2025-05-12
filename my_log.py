#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@文件    :my_log.py
@说明    :
@时间    :2024/07/17 15:08:05
@作者    :LevinKai
@版本    :1.0
'''

import sys
import os
# 获取当前文件所在目录的上一级路径
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
print(f'parent_dir:{parent_dir}')
if parent_dir:
    sys.path.insert(0, parent_dir)
    
import time
import logging
import logging.handlers
try:
    import config as CFG # type: ignore
except Exception as e:
    print(f'import config as CFG e"{e}')
    CFG = None
    
PARENT_DIR      = os.path.split(os.path.realpath(__file__))[0]  # 父目录
LOGGING_DIR     = os.path.join(PARENT_DIR, 'log' if CFG is None else CFG.LOG_DIR)  # 日志目录
LOGGING_NAME    = __file__  # 日志文件名

LOGGING_TO_FILE         = True  # 日志输出文件
LOGGING_TO_CONSOLE      = True  # 日志输出到控制台
LOGGING_CAPACITY        = 5000

# 日志文件切分大小 (50 * 1024 * 1024)
LOGGING_MAXBYTES = (50 * 1024 * 1024) if CFG is None else CFG.LOG_MAXBYTES
# 日志文件切分维度 'H'
LOGGING_WHEN = 'H' if CFG is None else CFG.LOG_WHEN
# 间隔少个 when 后，自动重建文件
LOGGING_INTERVAL  = 1
# 日志保留个数 (24*7+20)
LOGGING_BACKUP_COUNT = (24*7+20) if CFG is None else CFG.LOG_BACKUP_COUNT
# 日志等级 'INFO'
LOGGING_LEVEL  = logging.INFO if CFG is None else CFG.LOG_LEVEL
# 旧日志文件名
LOGGING_SUFFIX = "%Y-%m-%d_%H-%M-%S.log"

# 日志输出格式
LOGGING_FORMATTER = "%(asctime)s - %(filename)s - line:%(lineno)d - %(levelname)s - %(message)s"

# init = False
# memory_handler = None  # Declare memory_handler as a global variable

loggers = {}  # 存储所有 logger 对象

class MyMemoryHandler(logging.handlers.MemoryHandler):
    def __init__(self, size=LOGGING_MAXBYTES, capacity=LOGGING_CAPACITY, flushLevel=logging.ERROR, target=None):
        super().__init__(capacity, flushLevel, target)
        self.total_bytes = 0
        self.size = size
        self.last_flush_time = int(time.time())
        
    def shouldFlush(self, record):
        ret = False
        # """
        # Check for buffer full or a record at the flushLevel or higher.
        # """
        current_time = int(time.time())
        if(current_time - self.last_flush_time >= (60*60)):
            ret = True
        
        self.total_bytes += self.calculate_bytes(record)
        
        if(self.total_bytes >= self.size):
            ret = True
        
        if (len(self.buffer) >= self.capacity):
            ret = True
        
        if(record.levelno >= self.flushLevel):
            ret = True
        
        if ret:
            self.last_flush_time = current_time
            self.total_bytes = 0
        return ret
    
    def calculate_bytes(self, record):
        # 自定义计算日志记录所占用的字节数的方法
        # 这里可以根据需要修改，例如按照一定的估算方式计算日志的字节数
        return len(self.format(record))
    
class SizeAndTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    def __init__(self, filename, when='h', interval=1, backupCount=0, maxBytes=0, encoding=None, delay=False, utc=False, atTime=None):
        self.maxBytes = maxBytes
        self.backupCount = backupCount
        super().__init__(filename, when=when, interval=interval, backupCount=backupCount, encoding=encoding, delay=delay, utc=utc, atTime=atTime)
        
    def shouldRollover(self, record):
        if self.stream is None:  # delay was set
            self.stream = self._open()
        
        if self.maxBytes > 0:  # Are we rolling over?
            msg = "%s\n" % self.format(record)
            self.stream.seek(0, 2)  # due to non-posix-compliant Windows feature
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return True
        
        t = int(time.time())
        if t >= self.rolloverAt:
            return True
        
        return False

def get_logger(name="default"):
    return loggers.get(name)

def set_log_level(level=0, name="default"):
    logger = loggers.get(name)
    if logger:
        logger.setLevel(level)

def flush_log(name="default"):
    logger = loggers.get(name)
    if logger:
        for handler in logger.handlers:
            if isinstance(handler, logging.handlers.MemoryHandler):
                handler.flush()
                
def initLogging(log_file="", message=""):
    global loggers

    logger_name = log_file or "default"
    if logger_name in loggers:
        loggers[logger_name].info("logger already initialized")
        return loggers[logger_name]

    if not os.path.exists(LOGGING_DIR):
        os.makedirs(LOGGING_DIR)

    log_file_sanitized = log_file.replace(" ", "-").replace(":", "-") + ".log"
    log_path = os.path.join(LOGGING_DIR, log_file_sanitized)

    logger = logging.getLogger(logger_name)
    logger.setLevel(LOGGING_LEVEL)
    formatter = logging.Formatter(LOGGING_FORMATTER)

    if LOGGING_TO_FILE:
        file_handler = SizeAndTimedRotatingFileHandler(
            filename=log_path,
            when=LOGGING_WHEN,
            interval=LOGGING_INTERVAL,
            backupCount=LOGGING_BACKUP_COUNT,
            maxBytes=LOGGING_MAXBYTES
        )
        file_handler.suffix = LOGGING_SUFFIX
        file_handler.setFormatter(formatter)

        memory_handler = MyMemoryHandler(
            size=LOGGING_MAXBYTES,
            capacity=LOGGING_CAPACITY,
            flushLevel=logging.FATAL,
            target=file_handler
        )
        logger.addHandler(memory_handler)

    if LOGGING_TO_CONSOLE:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    logger.info(message or f"Logger {logger_name} initialized.")
    loggers[logger_name] = logger
    return logger

if __name__ == '__main__':
    initLogging('1234')
    time.sleep(1)
    logging.error("error")
    logging.info("info")
    logging.warning("warn")
    logging.debug("info")
    time.sleep(1)
    
    set_log_level('DEBUG')  # type: ignore
    logging.error("error")
    logging.info("info")
    logging.warning("warn")
    logging.debug("info")
    
    # 确保程序退出前将所有日志刷新到目标处理器
    flush_log()
