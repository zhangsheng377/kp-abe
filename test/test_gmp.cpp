#include <iostream>
#include <gmp.h>

int main()
{
    mpz_t temp;
    mpz_init(temp);
    mpz_set_ui(temp, (rand() % 100) + 1);
    gmp_printf("The public h=%Zd\n", temp);
    mpz_clear(temp);

    return 0;
}