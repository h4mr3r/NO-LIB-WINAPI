#include "string_utilities.h"

unsigned int strlen(const char *str) {
    unsigned int length = 0;

    while (str[length] != '\0') {
        length++;
    }

    return length;
}