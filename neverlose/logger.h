#ifndef NEVERLOSE_LOGGER_H
#define NEVERLOSE_LOGGER_H
#include <ctime>
#include <string>
#include <iostream>
#include <iomanip>

#define ENTER_LOGGER(logger) logger.section(TEXT(__FUNCTION__))


class clogger
{
	std::wostream* stream;
    std::wstring name;
public:
    clogger(const wchar_t* section_name, std::wostream* output) : stream(output)
    {
        if (stream)
        {
            name = section_name;
            *stream << L"============= Section " << this->name << L" start =============\n";
        }
    };

    ~clogger()
    {
        if (stream)
            *stream << L"============= Section " << this->name << L" end =============\n";
    };

    template<typename T>
    clogger& operator<<(const T& in)
    {
        if (stream)
            *stream << in;
        return *this;
    };

    clogger& operator<<(std::wostream& (*manip)(std::wostream&))
    {
        if (stream)
            *stream << manip;
        return *this;
    };
};

class clog_manager
{
    std::wostream* stream;
public:
    clog_manager() : stream(nullptr) {};
    explicit clog_manager(std::wostream& output) : stream(&output)
    {
        std::time_t now = std::time(nullptr);
        tm newtime;
        localtime_s(&newtime, &now);
        std::ios::sync_with_stdio(false);
        *stream << L"Logger inited at " << std::put_time(&newtime, L"%Y-%m-%d %H:%M:%S") << '\n';
    };

    ~clog_manager()
    {
        if (!stream)
            return;

        std::time_t now = std::time(nullptr);
        tm newtime;
        localtime_s(&newtime, &now);

        *stream << L"Logger terminated at " << std::put_time(&newtime, L"%Y-%m-%d %H:%M:%S");
        stream->flush();
    };

    clogger section(const wchar_t* section_name)
    {
        return clogger(section_name, stream);
    };
};

#endif // NEVERLOSE_LOGGER_H
