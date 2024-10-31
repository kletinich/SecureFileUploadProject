#include "ClientHandler.h"

int main()
{
    cout << "Client test Daniel Kletinich 208382739" << endl;
    ClientHandler* client = new ClientHandler();
    client->startClient();

    delete(client);
}