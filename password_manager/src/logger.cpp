#include "logger.h"

SyslogSession::SyslogSession() {
    openlog("password_manager", LOG_PID | LOG_NDELAY, LOG_USER);
}

SyslogSession::~SyslogSession() {
    closelog();
}

void logEvent(int priority, const std::string& message) {
    syslog(priority, "%s", message.c_str());
}
