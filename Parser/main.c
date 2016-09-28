#include "map.h"

int main(int argc, char* argv[])
{
    MAP map;
    int status;

    if (argc < 2)
    {
        printf("Usage: %s filename\n", argv[0]);
        return 0;
    }

    status = MapFile(argv[1], 
                     GENERIC_READ | GENERIC_WRITE,
                     &map);

    if (!MAP_SUCCESS(status))
    {
        printf("MapFile failed\n");
        goto Cleanup;
    }

    ProcessPE(&map);

Cleanup:
    UnmapFile(&map);

//	printf("\nPress any key...");
//	getchar();

    return 0;
}
