#include <locale.h>
#include <stdio.h>
#include <wchar.h>

int
main(void)
{
        setlocale(6, "en_US.UTF-8");
        printf("%d\n", fgetwc(stdin));
        return 0;
}
