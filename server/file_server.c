#include "server.h"

int serve_file(char *read, char **file_buf, int *file_len) {
  char file_name[256];
  strcpy(file_name, "./file_folder/");
  strncat(file_name, read, 256);
  
  FILE *file = fopen(file_name, "r");
  if (file != NULL) {
    printf("File %s has been opened.\n", file_name);
  } else {
    return -1;
  }
  fseek(file, 0L, SEEK_END);
  *file_len = ftell(file);
  char header[10];
  snprintf(header, 10, "%d", *file_len);
  fseek(file, 0L, SEEK_SET);
  *file_buf = malloc(*file_len+strlen(header));
  strcpy(*file_buf, header);
  fread(*file_buf+strlen(header), 1, *file_len, file);
  fclose(file);
  *file_len += strlen(header);
  return 1;
}

int main() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    fprintf(stderr, "SSL_CTX_new() failed.\n");
    return 1;
  }

  if (!SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM)
  || !SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM)) {
    fprintf(stderr, "SSL_CTX_use_certificate_file() failed.\n");
    ERR_print_errors_fp(stderr);
    return 1;
  }

  printf("Configuring local address...\n");
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  struct addrinfo *bind_address;
  getaddrinfo(0, "8080", &hints, &bind_address);
  printf("Creating socket...\n");
  SOCKET socket_listen;
  socket_listen = socket(bind_address->ai_family, bind_address->ai_socktype, bind_address->ai_protocol);
  if (!ISVALIDSOCKET(socket_listen)) {
    fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
    return 1;
  }

  printf("Binding socket to local address...\n");
  if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
    fprintf(stderr, "bind() failed. (%d)\n", GETSOCKETERRNO());
    return 1;
  }
  freeaddrinfo(bind_address);

  printf("Listening...\n");
  if (listen(socket_listen, 10) < 0) {
    fprintf(stderr, "listen() failed. (%d)\n", GETSOCKETERRNO());
    return 1;
  }

  fd_set master;
  FD_ZERO(&master);
  FD_SET(socket_listen, &master);
  SOCKET max_socket = socket_listen;

  printf("Waiting for connections...\n");
  while(1) {
    fd_set reads;
    reads = master;
    if (select(max_socket + 1, &reads, 0, 0, 0) < 0) {
      fprintf(stderr, "select() failed. (%d)\n", GETSOCKETERRNO());
      return 1;
    }
    SOCKET i;
    for (i = 1; i <= max_socket; ++i) {
      if (FD_ISSET(i, &reads)) {
        if (i == socket_listen) {
          struct sockaddr_storage client_address;
          socklen_t client_len = sizeof(client_address);
          SOCKET socket_client = accept(socket_listen, (struct sockaddr*) &client_address, &client_len);
          if (!ISVALIDSOCKET(socket_client)) {
            fprintf(stderr, "accept() failed (%d)\n", GETSOCKETERRNO());
            return 1;
          }
          FD_SET(socket_client, &master);
          if (socket_client > max_socket) {
            max_socket = socket_client;
          }
          char address_buffer[100];
          getnameinfo((struct sockaddr*) &client_address, client_len, address_buffer, sizeof(address_buffer), 0, 0, NI_NUMERICHOST);
          printf("New connection from %s\n", address_buffer);
	} else {
	  
	  SSL *ssl = SSL_new(ctx);
	  if (!ssl) {
	    fprintf(stderr, "SSL_new() failed.\n");
	    return 1;
	  }

	  SSL_set_fd(ssl, i);
	  if (SSL_accept(ssl) <= 0) {
	    fprintf(stderr, "SSL_accept() failed.\n");
	    ERR_print_errors_fp(stderr);

	    SSL_shutdown(ssl);
	    CLOSESOCKET(i);
	    SSL_free(ssl);
	    continue;
	  }

	  printf("SSL connection using %s\n", SSL_get_cipher(ssl));
          
	  char read[1025];
          int bytes_received = SSL_read(ssl, read, 1024);
          if (bytes_received < 1) {
            FD_CLR(i, &master);
            CLOSESOCKET(i);
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
            continue;
          }
          read[bytes_received] = '\0';
          int file_len = 0;
          char *file_buf;
          char will_read[10];
          if (serve_file(read, &file_buf, &file_len) < 0) {
            file_buf = malloc(64);
	    snprintf(file_buf, 64,"%d", 29);
            strcat(file_buf, "Requested file doesn't exist\n");
            file_len = strlen(file_buf);
          }
          SSL_write(ssl, file_buf, file_len);
          free(file_buf);
	  SSL_shutdown(ssl);
	  SSL_free(ssl);
	  FD_CLR(i, &master);
	  CLOSESOCKET(i);
        }
      }
    }
  }
  printf("Closing listening socket...\n");
  SSL_CTX_free(ctx);
  CLOSESOCKET(socket_listen);
  printf("Finished.\n");
  return 0;
}
