#include "ulog_utils.h"
 
#include <log4cplus/logger.h>
#include <log4cplus/layout.h>
#include <log4cplus/fileappender.h>
#include <log4cplus/consoleappender.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

using namespace log4cplus;

#define MAX_FILE_SIZE 10*1024*1024
#define MAX_FILE_NUMBER 5
 
Logger logger = Logger::getInstance(LOG4CPLUS_TEXT("logmain"));
 
int initLogger(const char* logs_filename) 
{
    log4cplus::initialize ();

    if (logs_filename!=NULL)
    {
        if (access(EHSM_LOGS_FOLDER, F_OK) != 0) {
            printf("Initializing logs folder [path: %s].", EHSM_LOGS_FOLDER);
            if (mkdir(EHSM_LOGS_FOLDER, 0755) != 0) {
                printf("Create logs folder failed!");
                return -1;
            }
        }

        printf("Logs folder:\t%s\n", EHSM_LOGS_FOLDER);
        int path_len = strlen(EHSM_LOGS_FOLDER) + strlen(logs_filename) + strlen("/")+1;
        char logs_path[path_len] = {0};        
        snprintf(logs_path, path_len, "%s/%s", EHSM_LOGS_FOLDER, logs_filename);

        SharedAppenderPtr fileAppender(new RollingFileAppender(
                                    LOG4CPLUS_TEXT(logs_path), 
                                    MAX_FILE_SIZE, 
                                    MAX_FILE_NUMBER));
        fileAppender->setName(LOG4CPLUS_TEXT("file"));
        log4cplus::tstring filePattern = LOG4CPLUS_TEXT("%h %d{%m/%d/%y %H:%M:%S,%q} %-4p %m %n");
        fileAppender->setLayout(std::auto_ptr<Layout>(new PatternLayout(filePattern)));
        Logger::getRoot().addAppender(fileAppender);
    }

    SharedAppenderPtr consoleAppender(new log4cplus::ConsoleAppender);
    consoleAppender->setName(LOG4CPLUS_TEXT("console"));
    log4cplus::tstring consolePattern = LOG4CPLUS_TEXT("%h %d{%m/%d/%y %H:%M:%S,%q} %-4p %m %n");
    consoleAppender->setLayout(std::auto_ptr<Layout>(new PatternLayout(consolePattern)));

    if (IS_DEBUG)
    {
        logger.setLogLevel(log4cplus::DEBUG_LOG_LEVEL);
    }
    else
    {
        logger.setLogLevel(log4cplus::INFO_LOG_LEVEL);
    }    

    Logger::getRoot().addAppender(consoleAppender);

    return 0;
}

void do_logger(LogLevel logLevel,
               const char *filename,
               int line,
               int bufSize,
               const char* pFormat, ...)
{
    if(logger.isEnabledFor(logLevel))
    {                
        va_list args;            
        va_start(args, pFormat);        
        char buf[bufSize] = {0};        
        vsnprintf(buf, bufSize, pFormat, args);    
        va_end(args);           
        char msg[bufSize] = {0};        
        sprintf(msg,"[%s: line %d] - %s", filename, line, buf);    
        logger.forcedLog(logLevel, msg);
    }
}

void logger_shutDown(){
    log4cplus::Logger::shutdown();
}