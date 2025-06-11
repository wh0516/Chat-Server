#include "server.hpp"

void help()
{
    printf("exp: ./serverApp 8000");
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        help();
    }
    if (argc == 2)
    {
        Server serverApp(argv[1]);
        serverApp.run();
    }
}