/*
Copyright (c) 2018 Xiao Wang (wangxiao@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Enquiries about further applications and development opportunities are welcome.
*/

#ifndef NETWORK_IO_CHANNEL
#define NETWORK_IO_CHANNEL

#include "utils/exit_codes.h"
#include "utils/io_channel.h"
#include <chrono>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <memory> // std::align
using std::string;

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

enum class LastCall { None, Send, Recv };

namespace sci {
/** @addtogroup IO
  @{
 */

class NetIO : public IOChannel<NetIO> {
public:
  bool is_server;
  int mysocket = -1;
  int consocket = -1;
  FILE *stream = nullptr;
  char *buffer = nullptr;
  bool has_sent = false;
  string addr;
  int port;
  uint64_t num_rounds = 0;
  LastCall last_call = LastCall::None;
  NetIO(const char *address, int port, bool quiet = false) {
    this->port = port;
    is_server = (address == nullptr);
    if (address == nullptr) {
      struct sockaddr_in dest;
      struct sockaddr_in serv;
      socklen_t socksize = sizeof(struct sockaddr_in);
      memset(&serv, 0, sizeof(serv));
      serv.sin_family = AF_INET;
      serv.sin_addr.s_addr =
          htonl(INADDR_ANY);       /* set our address to any interface */
      serv.sin_port = htons(port); /* set the server port number */
      mysocket = socket(AF_INET, SOCK_STREAM, 0);
      int reuse = 1;
      setsockopt(mysocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
                 sizeof(reuse));
      if (::bind(mysocket, (struct sockaddr *)&serv, sizeof(struct sockaddr)) <
          0) {
        perror("[error] bind failed");
        fprintf(stderr, "[error] --> status-code: %d\n", sci::EXIT_BIND_LISTEN_FAILURE);
        exit(sci::EXIT_BIND_LISTEN_FAILURE);
      }
      if (listen(mysocket, 1) < 0) {
        perror("[error] listen failed");
        fprintf(stderr, "[error] --> status-code: %d\n", sci::EXIT_BIND_LISTEN_FAILURE);
        exit(sci::EXIT_BIND_LISTEN_FAILURE);
      }
      consocket = accept(mysocket, (struct sockaddr *)&dest, &socksize);
      close(mysocket);
    } else {
      addr = string(address);

      struct sockaddr_in dest;
      memset(&dest, 0, sizeof(dest));
      dest.sin_family = AF_INET;
      dest.sin_addr.s_addr = inet_addr(address);
      dest.sin_port = htons(port);

      auto connect_start = std::chrono::steady_clock::now();
      constexpr int connect_timeout_sec = 10;
      while (1) {
        consocket = socket(AF_INET, SOCK_STREAM, 0);

        if (connect(consocket, (struct sockaddr *)&dest,
                    sizeof(struct sockaddr)) == 0) {
          break;
        }

        close(consocket);

        auto elapsed = std::chrono::steady_clock::now() - connect_start;
        if (elapsed >= std::chrono::seconds(connect_timeout_sec)) {
          fprintf(stderr,
                  "[error] failed to connect to client (%s:%d) after %d seconds\n"
                  "[error] --> status-code: %d\n",
                  address, port, connect_timeout_sec, sci::EXIT_CONNECT_TIMEOUT);
          exit(sci::EXIT_CONNECT_TIMEOUT);
        }

        usleep(1000);
      }
    }
    set_nodelay();
    stream = fdopen(consocket, "wb+");
    buffer = new char[NETWORK_BUFFER_SIZE];
    memset(buffer, 0, NETWORK_BUFFER_SIZE);
	// NOTE(Zhicong): we need _IONBF for the best network performance
    setvbuf(stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE);
    if (!quiet)
      std::cout << "connected\n";
  }

  void sync() {
    int tmp = 0;
    if (is_server) {
      send_data_internal(&tmp, 1);
      recv_data_internal(&tmp, 1);
    } else {
      recv_data_internal(&tmp, 1);
      send_data_internal(&tmp, 1);
      flush();
    }
  }

  ~NetIO() {
    fflush(stream);
    close(consocket);
    delete[] buffer;
  }

  void set_nodelay() {
    const int one = 1;
    setsockopt(consocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  }

  void set_delay() {
    const int zero = 0;
    setsockopt(consocket, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));
  }

  void flush() { fflush(stream); }

  void send_data_internal(const void *data, int len) {
    if (last_call != LastCall::Send) {
      num_rounds++;
      last_call = LastCall::Send;
    }
    int sent = 0;
    while (sent < len) {
      int res = fwrite(sent + (char *)data, 1, len - sent, stream);
      if (res > 0) {
        sent += res;
      } else {
        fprintf(stderr, "[error] connection lost during send (%d/%d bytes sent)\n"
                        "[error] --> status-code: %d\n", sent, len, sci::EXIT_CONNECTION_LOST);
        exit(sci::EXIT_CONNECTION_LOST);
      }
    }
    has_sent = true;
  }

  void recv_data_internal(void *data, int len) {
    if (last_call != LastCall::Recv) {
      num_rounds++;
      last_call = LastCall::Recv;
    }
    if (has_sent)
      fflush(stream);
    has_sent = false;
    int sent = 0;
    while (sent < len) {
      int res = fread(sent + (char *)data, 1, len - sent, stream);
      if (res > 0) {
        sent += res;
      } else {
        fprintf(stderr, "[error] connection lost during recv (%d/%d bytes received)\n"
                        "[error] --> status-code: %d\n", sent, len, sci::EXIT_CONNECTION_LOST);
        exit(sci::EXIT_CONNECTION_LOST);
      }
    }
  }
};
/**@}*/

} // namespace sci
#endif // NETWORK_IO_CHANNEL
