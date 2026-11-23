#pragma once

#include <string>

#include <syslog.h>

class SyslogSession {
public:
    SyslogSession();
    ~SyslogSession();

    SyslogSession(const SyslogSession&) = delete;
    SyslogSession& operator=(const SyslogSession&) = delete;
};

void logEvent(int priority, const std::string& message);
