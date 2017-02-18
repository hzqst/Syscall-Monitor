#pragma once
#include <string>
std::wstring UTF8ToUnicode(std::string &str);
std::wstring ANSIToUnicode(std::string &str);
std::string UnicodeToUTF8(std::wstring &str);
std::string UnicodeToANSI(std::wstring &str);

std::string UrlEncode(const std::string& str);
std::string UrlDecode(const std::string& str);
std::string Base64_Encode(const unsigned char* Data, size_t DataByte);
std::string Base64_Decode(const char* Data, size_t DataByte);