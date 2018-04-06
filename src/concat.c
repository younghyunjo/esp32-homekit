#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "concat.h"

uint8_t* concat3(uint8_t* m1, int m1_len, 
        uint8_t* m2, int m2_len, 
        uint8_t* m3, int m3_len, int* concateated_len)
{
    *concateated_len = m1_len + m2_len + m3_len;
    uint8_t* concatenated = malloc(*concateated_len);
    if (concatenated == NULL) {
        printf("malloc failed\n");
        *concateated_len = 0;
        return NULL;
    }

    memcpy(concatenated, m1, m1_len);
    memcpy(concatenated + m1_len, m2, m2_len);
    memcpy(concatenated + m1_len + m2_len, m3, m3_len);

    return concatenated;
}

void concat_free(uint8_t* concatenated)
{
    if (concatenated)
        free(concatenated);
}
