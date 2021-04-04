#include "client.h"

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "usage: file_client hostname filename\n");
    return 1;
  }

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    fprintf(stderr, "SSL_CTX_new() failed.\n");
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

  printf("Creating socket...\n");
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

  SSL *ssl = SSL_new(ctx);
  if (!ctx) {
    fprintf(stderr, "SSL_new() failed.\n");
    return 1;
  }

  SSL_set_fd(ssl, socket_peer);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "SSL_connect() failed.\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  printf("SSL/TLS is using %s\n", SSL_get_cipher(ssl));

  printf("Connected.\n");
  
  SSL_write(ssl, argv[2], strlen(argv[2]));
  
  char read[4096];
  int bytes_received = SSL_read(ssl, read, 4096);
  if (bytes_received < 1) {
    printf("Connection closed by peer.\n");
  } else {
    char *pointer;
    int will_read = strtol(read, &pointer, 10);
    if (pointer != read) {
      //OK
      bytes_received -= pointer-read;
      printf("Receiving %d bytes\n", will_read);
      printf("%*s", bytes_received, pointer);
    }
  }

  printf("Closing socket...\n");
  SSL_shutdown(ssl);
  CLOSESOCKET(socket_peer);
  SSL_free(ssl);

  SSL_CTX_free(ctx);

  printf("Finished.");
  return 0;
}
