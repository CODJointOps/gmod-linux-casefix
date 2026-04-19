#include "casefix_log.h"

#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <sys/types.h>
#include <unistd.h>

namespace casefix_log {
namespace {

std::mutex& log_mutex() {
    static std::mutex mutex;
    return mutex;
}

constexpr const char* k_log_path = "/tmp/gmod_casefix.log";

} // namespace

const char* path() {
    return k_log_path;
}

void write(std::string_view helper_name, const char* fmt, ...) {
    std::lock_guard lock(log_mutex());

    FILE* file = std::fopen(k_log_path, "a");
    if (!file) {
        return;
    }

    std::time_t now = std::time(nullptr);
    char time_buf[32] = {};
    if (const std::tm* tm = std::localtime(&now)) {
        std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm);
    } else {
        std::snprintf(time_buf, sizeof(time_buf), "time-error");
    }

    std::fprintf(file, "[%s][pid=%d][%.*s] ",
        time_buf,
        static_cast<int>(::getpid()),
        static_cast<int>(helper_name.size()),
        helper_name.data());

    va_list args;
    va_start(args, fmt);
    std::vfprintf(file, fmt, args);
    va_end(args);

    std::fputc('\n', file);
    std::fclose(file);
}

} // namespace casefix_log

