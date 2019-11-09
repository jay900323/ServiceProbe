#pragma once
#include <vector>
#include <string>

char* cstring_unescape(char* str, unsigned int* newlen);
std::vector<std::string> split(const std::string& s, const std::string& c);
