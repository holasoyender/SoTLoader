#pragma once

#include "color.h"

namespace logger {

    std::string FILE_NAME = "logs/SoTLoader.log";

    template<typename = std::string>
    std::string getDateFormatted() {

        time_t rawtime;
        struct tm timeinfo;
        char buffer[80];


        time(&rawtime);
        localtime_s(&timeinfo, &rawtime);

        strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", &timeinfo);
        std::string str(buffer);

        return str;
    }

    template<typename... Args>
    void info(Args &&... args) {
        std::cout << dye::grey(getDateFormatted()) << " " << dye::yellow("info") << ": ";
        (std::cout << ... << std::forward<Args>(args)) << '\n';

        std::ofstream log_file(FILE_NAME, std::ios_base::out | std::ios_base::app);
        log_file << getDateFormatted() << " info: ";
        (log_file << ... << std::forward<Args>(args)) << '\n';

        log_file.close();
    }

    template<typename... Args>
    void warn(Args &&... args) {
        std::cout << dye::grey(getDateFormatted()) << " " << dye::yellow("warn") << ": ";
        (std::cout << ... << std::forward<Args>(args)) << '\n';

        std::ofstream log_file(FILE_NAME, std::ios_base::out | std::ios_base::app);
        log_file << getDateFormatted() << " warn: ";
        (log_file << ... << std::forward<Args>(args)) << '\n';

        log_file.close();
    }

    template<typename... Args>
    void error(Args &&... args) {
        std::cout << dye::grey(getDateFormatted()) << " " << dye::red("error") << ": ";
        (std::cout << ... << std::forward<Args>(args)) << '\n';

        std::ofstream log_file(FILE_NAME, std::ios_base::out | std::ios_base::app);
        log_file << getDateFormatted() << " error: ";
        (log_file << ... << std::forward<Args>(args)) << '\n';

        log_file.close();
    }

}