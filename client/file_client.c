#include "client.h"

int read_from_socket(char *pointer, int already_buf, long will_read, SOCKET socket_peer) {
  printf("%.*s", already_buf, pointer);
  //TODO: Complete function
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "usage: file_client hostname filename\n");
    return 1;
  }
  
  printf("Configuring remote address...\n");
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  
  struct addrinfo *peer_address;
  if (getaddrinfo(argv[1], "8080", &hints, &peer_address)) {
    fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
    return 1;
  }

  printf("Remote address is: ");
  char address_buffer[100];
  char service_buffer[100];
  getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen, address_buffer, sizeof(address_buffer), service_buffer, sizeof(service_buffer), NI_NUMERICHOST);
  printf("%s %s\n", address_buffer, service_buffer);

  printf("Creatin socket...\n");
  SOCKET socket_peer;
  socket_peer = socket(peer_address->ai_family, peer_address->ai_socktype, peer_address->ai_protocol);
  if (!ISVALIDSOCKET(socket_peer)) {
    fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
    return 1;
  }
  printf("Connecting...\n");
  if (connect(socket_peer, peer_address->ai_addr, peer_address->ai_addrlen)) {
    fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
    return 1;
  }
  freeaddrinfo(peer_address);

  printf("Connected.\n");
  
  send(socket_peer, argv[2], strlen(argv[2]), 0);
  
  char read[4096];
  int bytes_received = recv(socket_peer, read, 4096, 0);
  if (bytes_received < 1) {
    printf("Connection closed by peer.\n");
  } else {
    char *pointer;
    long will_read = strtol(read, &pointer, 10);
    if (pointer != read) {
      //OK
      bytes_received -= pointer-read;
      printf("Receiving %ld bytes\n", will_read);
      read_from_socket(pointer, bytes_received, will_read, socket_peer);
    }
  }

  printf("Closing socket...\n");
  CLOSESOCKET(socket_peer);

  printf("Finished.");
  return 0;
}
