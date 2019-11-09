#include "utils.h"

#include <ctype.h>

/* A simple function to form a character from 2 hex digits in ASCII form. */
static unsigned char hex2char(unsigned char a, unsigned char b) {
	int val;

	if (!isxdigit((int)a) || !isxdigit((int)b))
		return 0;
	a = tolower((int)a);
	b = tolower((int)b);
	if (isdigit((int)a))
		val = (a - '0') << 4;
	else
		val = (10 + (a - 'a')) << 4;

	if (isdigit((int)b))
		val += (b - '0');
	else
		val += 10 + (b - 'a');

	return (unsigned char)val;
}

char* cstring_unescape(char* str, unsigned int* newlen) 
{
	char* dst = str, *src = str;
	char newchar;

	while (*src) {
		if (*src == '\\') {
			src++;
			switch (*src) {
			case '0':
				newchar = '\0';
				src++;
				break;
			case 'a': // Bell (BEL)
				newchar = '\a';
				src++;
				break;
			case 'b': // Backspace (BS)
				newchar = '\b';
				src++;
				break;
			case 'f': // Formfeed (FF)
				newchar = '\f';
				src++;
				break;
			case 'n': // Linefeed/Newline (LF)
				newchar = '\n';
				src++;
				break;
			case 'r': // Carriage Return (CR)
				newchar = '\r';
				src++;
				break;
			case 't': // Horizontal Tab (TAB)
				newchar = '\t';
				src++;
				break;
			case 'v': // Vertical Tab (VT)
				newchar = '\v';
				src++;
				break;
			case 'x':
				src++;
				if (!*src || !*(src + 1)) return NULL;
				if (!isxdigit((int)(unsigned char)* src) || !isxdigit((int)(unsigned char) * (src + 1))) return NULL;
				newchar = hex2char(*src, *(src + 1));
				src += 2;
				break;
			default:
				if (isalnum((int)(unsigned char)* src))
					return NULL; // I don't really feel like supporting octals such as \015
								 // Other characters I'll just copy as is
				newchar = *src;
				src++;
				break;
			}
			*dst = newchar;
			dst++;
		}
		else {
			if (dst != src)
				* dst = *src;
			dst++;
			src++;
		}
	}
	*dst = '\0'; // terminated, but this string can include other \0, so use newlen
	if (newlen)
		* newlen = dst - str;

	return str;
}

std::vector<std::string> split(const std::string& s, const std::string& c)
{
	std::vector<std::string> v;
	std::string::size_type pos1, pos2;
	pos2 = s.find(c);
	pos1 = 0;
	while (std::string::npos != pos2)
	{
		v.push_back(s.substr(pos1, pos2 - pos1));
		pos1 = pos2 + c.size();
		pos2 = s.find(c, pos1);
	}
	if (pos1 != s.length())
		v.push_back(s.substr(pos1));

	return v;
}