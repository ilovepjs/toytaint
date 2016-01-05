#include "toytaint.h"
int main(int argc, char **argv)
{
    int a = 123121;
    TT_MAKE_MEM_TAINTED(&a,4);
    a = 1212121;
    int s = a + 1212121;
    TT_MAKE_MEM_UNTAINTED(&a,4);
    return 1;
}
