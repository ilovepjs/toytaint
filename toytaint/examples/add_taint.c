// An example program to show how taint sources are added

#include <stdio.h>

// Pre: Input is not malformed
int main(void)
{
    int d1, d2;
    printf("Please enter digit 1: ");
    scanf("%d", &d1);
    printf("Please enter digit 2: ");
    scanf("%d", &d2);

    printf("You entered %d and %d\n", d1, d2);
    return 0;
}
