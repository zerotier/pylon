// (c) 2020-2023 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

// HACK! Will eventually use epoll() or something in Phy<> instead of select().
// Also be sure to change ulimit -n and fs.file-max in /etc/sysctl.conf on relays.
#if defined(__linux__) || defined(__LINUX__) || defined(__LINUX) || defined(LINUX)
#include <bits/types.h>
#include <linux/posix_types.h>
#undef __FD_SETSIZE
#define __FD_SETSIZE 1048576
#undef FD_SETSIZE
#define FD_SETSIZE 1048576
#endif

#include "Phy.hpp"

#define ZT_TCP_PROXY_CONNECTION_TIMEOUT_SECONDS 300
#define ZT_TCP_PROXY_TCP_PORT					443
#define INVALID_SOCKET_FD						-1

#include "ZeroTierSockets.h"
#include "ext/libzt/ext/ZeroTierOne/node/Mutex.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <errno.h>
#include <fcntl.h>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <set>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#define SOCKS_OPEN		   0x00
#define SOCKS_CONNECT_INIT 0x01
#define SOCKS_CONNECT_IPV4 0x02
#define SOCKS_UDP		   0x03
#define SOCKS_COMPLETE	   0x04
#define CONNECTION_TIMEOUT 0x05

#define SOCKS_IDX_VERSION 0x00
#define IDX_COMMAND		  0x01
#define IDX_METHOD		  0x01
#define IDX_FRAG		  0x01
#define IDX_ERROR_CODE	  0x01
#define IDX_NMETHODS	  0x01
#define IDX_METHODS		  0x02	 // Supported methods
#define IDX_ATYP		  0x03
#define IDX_DST_ADDR	  0x04

#define THIS_PROXY_VERSION 0x5

#define REPLY_LEN			  10
#define CONNECT_TIMEOUT_S	  10
#define MAX_ADDR_LEN		  32
#define PORT_LEN			  2
#define LISTEN_BACKLOG		  32
#define MAX_PROXY_CONNECTIONS 256
#define BUF_SIZE			  (16 * 1024)
#define SLEEP_INTERVAL		  5000
#define POLL_TIMEOUT_MS		  (500)

#define ZT_FILENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define ZT_RED	 "\x1B[31m"
#define ZT_GRN	 "\x1B[32m"
#define ZT_YEL	 "\x1B[33m"
#define ZT_BLU	 "\x1B[34m"
#define ZT_MAG	 "\x1B[35m"
#define ZT_CYN	 "\x1B[36m"
#define ZT_WHT	 "\x1B[37m"
#define ZT_RESET "\x1B[0m"

#define LOG_INFO(fmt, args...)	fprintf(stderr, ZT_WHT "%17s:%06d:%25s: " fmt "\n" ZT_RESET, ZT_FILENAME, __LINE__, __FUNCTION__, ##args)
#define LOG_WARN(fmt, args...)	fprintf(stderr, ZT_YEL "%17s:%06d:%25s: " fmt "\n" ZT_RESET, ZT_FILENAME, __LINE__, __FUNCTION__, ##args)
#define LOG_ERROR(fmt, args...) fprintf(stderr, ZT_RED "%17s:%06d:%25s: " fmt "\n" ZT_RESET, ZT_FILENAME, __LINE__, __FUNCTION__, ##args)

#ifdef PYLON_DEBUG
#define LOG_DEBUG(fmt, args...) fprintf(stderr, ZT_WHT "%17s:%06d:%25s: " fmt "\n" ZT_RESET, ZT_FILENAME, __LINE__, __FUNCTION__, ##args)
#else
#if defined(_WIN32)
#define LOG_DEBUG(...)
#else
#define LOG_DEBUG(fmt, args...)
#endif
#endif

ZeroTier::Mutex conn_m;

void* handle_proxy_conn(void* conn_ptr);

enum ConnectDirection { ToZeroTierNetwork, ToLocalAreaNetwork };

struct proxy_connection {
  int state;

  pthread_t handler;
  ConnectDirection direction;

  int fused_closed;	// Whether this fused socket has been closed
  bool shouldStop;

  bool rxStopped;
  bool txStopped;

  int fd_lan;
  int fd_zan;	  // end of socketpair that OS can read and write to (data on this socket is forwarded to and from the ZAN)
  int fd_zts;	  // libzt non-OS socket
  int fd_int;	  // end of socketpair that helper will read and write to
};

struct proxy_connection connections[MAX_PROXY_CONNECTIONS];
pthread_t threads[MAX_PROXY_CONNECTIONS];

// Retrieve data from libzt

void* fused_socket_tx_helper(void* ptr)
{
  struct proxy_connection* conn = (struct proxy_connection*)ptr;
  while (! conn->shouldStop && ! conn->fused_closed) {
    LOG_DEBUG("0x%p A <--- Z: (%2d, %2d, %2d): polling", conn, conn->fd_zan, conn->fd_int, conn->fd_zts);
    struct zts_pollfd fds[1];
    int nfds = 1;
    memset(fds, 0, sizeof(fds));
    fds[0].fd = conn->fd_zts;
    fds[0].events = ZTS_POLLIN;

    int rc = zts_bsd_poll(fds, nfds, POLL_TIMEOUT_MS);

    if (rc < 0) {
      LOG_ERROR("0x%p A <--- Z: poll() failed", conn);
      // perror("");
      usleep(SLEEP_INTERVAL);
      continue;
    }
    if (rc == 0) {
      LOG_DEBUG("0x%p A <--- Z: rc==0", conn);
      usleep(SLEEP_INTERVAL);
      continue;
    }

    for (int i = 0; i < nfds; i++) {
      if (fds[i].revents == 0) {
        LOG_DEBUG("0x%p A <--- Z: revents==0", conn);
        usleep(SLEEP_INTERVAL);
        continue;
      }
      if (fds[i].revents != ZTS_POLLIN) {
        LOG_DEBUG("0x%p A <--- Z: != ZTS_POLLIN", conn);
        usleep(SLEEP_INTERVAL);
        break;
      }
      if (fds[i].fd == conn->fd_zts) {
        usleep(SLEEP_INTERVAL);
        LOG_DEBUG("0x%p A <--- Z: reading from fused zt socket", conn);
        char rx_from_zt_buf[BUF_SIZE];
        int r = zts_read(conn->fd_zts, rx_from_zt_buf, sizeof(rx_from_zt_buf));
        if (r < 0) {
          LOG_DEBUG("0x%p A <--- Z: from fused zt socket (%d)", conn, r);
          // perror("");
          close(conn->fd_int);
          conn->fused_closed = 1;
        }
        if (r > 0) {
          int w = write(conn->fd_int, rx_from_zt_buf, r);
          if (w < 0) {
            LOG_ERROR("0x%p A <--- Z: to zt socket", conn);
            // perror("");
          }
          if (w > 0) {
            LOG_DEBUG("0x%p A <--- Z: wrote %d", conn, w);
          }
        }
      }
    }
  }
  conn->txStopped = true;
  LOG_DEBUG("0x%p A <--- Z: (%2d, %2d, %2d): stopping thread", conn, conn->fd_zan, conn->fd_int, conn->fd_zts);
  return NULL;
}

// Feed data into libzt

void* fused_socket_rx_helper(void* ptr)
{
  struct proxy_connection* conn = (struct proxy_connection*)ptr;
  while (! conn->shouldStop && ! conn->fused_closed) {
    LOG_DEBUG("0x%p A ---> Z: (%2d, %2d, %2d): polling", conn, conn->fd_zan, conn->fd_int, conn->fd_zts);
    struct pollfd fds[1];
    int nfds = 1;
    memset(fds, 0, sizeof(fds));
    fds[0].fd = conn->fd_int;
    fds[0].events = POLLIN;
    int rc = poll(fds, nfds, POLL_TIMEOUT_MS);

    if (rc < 0) {
      LOG_ERROR("0x%p A ---> Z:  poll failed", conn);
      // perror("");
      usleep(SLEEP_INTERVAL);
      continue;
    }
    if (rc == 0) {
      continue;
    }

    for (int i = 0; i < nfds; i++) {
      if (fds[i].revents == 0) {
        continue;
      }
      if (fds[i].revents != POLLIN) {
        usleep(SLEEP_INTERVAL);
      }
      if (fds[i].fd == conn->fd_int) {
        usleep(SLEEP_INTERVAL);
        LOG_DEBUG("0x%p A ---> Z:  reading from fused client socket", conn);
        char rx_from_client_buf[BUF_SIZE];
        int r = read(conn->fd_int, rx_from_client_buf, sizeof(rx_from_client_buf));
        if (r < 0) {
          LOG_DEBUG("0x%p A ---> Z: from fused client socket (%d)", conn, r);
          // perror("");
        }
        if (r > 0) {
          int w = zts_write(conn->fd_zts, rx_from_client_buf, r);
          if (w < 0) {
            LOG_ERROR("0x%p A ---> Z: to zt socket", conn);
            // perror("");
            close(conn->fd_int);
            conn->fused_closed = 1;
          }
          if (w > 0) {
            LOG_DEBUG("0x%p A ---> Z: wrote %d", conn, w);
          }
        }
      }
    }
  }
  conn->rxStopped = true;
  LOG_DEBUG("0x%p A ---> Z: (%2d, %2d, %2d): stopping thread", conn, conn->fd_zan, conn->fd_int, conn->fd_zts);
  return NULL;
}

int zts_fused_socket(int fd_pre_existing, struct proxy_connection* conn)
{
  if (! conn) {
    LOG_ERROR("invalid connection object provided");
    return -1;
  }

  int fd_zts = INVALID_SOCKET_FD;

  if (fd_pre_existing > 0) {
    fd_zts = fd_pre_existing;
  }
  else {
    fd_zts = zts_socket(AF_INET, SOCK_STREAM, 0);
  }
  // Create zt socket
  if (fd_zts < 0) {
    LOG_ERROR("Failed to create zt socket");
    return fd_zts;
  }
  conn->fd_zts = fd_zts;
  // Create socket pair
  int sockets[2];
  int err = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
  if (err < 0) {
    LOG_ERROR("Failed to create socket pair");
    return err;
  }
  conn->fd_zan = sockets[0];
  conn->fd_int = sockets[1];
  conn->fused_closed = 0;

  LOG_DEBUG("fused socket (%d) : [%d:%d <---> %d]", conn->fd_zan, conn->fd_zan, conn->fd_int, conn->fd_zts);

  pthread_t tx_thread;
  pthread_create(&tx_thread, NULL, fused_socket_tx_helper, (void*)conn);
  pthread_t rx_thread;
  pthread_create(&rx_thread, NULL, fused_socket_rx_helper, (void*)conn);

  return 0;
}

void* get_in_addr(struct sockaddr* sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int add_proxy_client_conn(int fd_socks_client, ConnectDirection dir)
{
  conn_m.lock();
  // Find empty connection slot for new proxied connection
  int empty_slot = MAX_PROXY_CONNECTIONS;
  for (int i = 0; i < MAX_PROXY_CONNECTIONS; i++) {
    if (connections[i].state == SOCKS_OPEN) {
      empty_slot = i;
      break;
    }
  }
  if (empty_slot == MAX_PROXY_CONNECTIONS) {
    LOG_ERROR("Max number of proxied connections reached.");
    conn_m.unlock();
    return -1;	 //
  }
  LOG_INFO("0x%p New connection added to slot %d", (void*)&connections[empty_slot], empty_slot);
  if (dir == ConnectDirection::ToZeroTierNetwork) {
    connections[empty_slot].fd_lan = fd_socks_client;
  }
  if (dir == ConnectDirection::ToLocalAreaNetwork) {
    connections[empty_slot].fd_zan = fd_socks_client;
  }
  connections[empty_slot].state = SOCKS_OPEN;
  connections[empty_slot].direction = dir;
  connections[empty_slot].shouldStop = false;
  connections[empty_slot].rxStopped = false;
  connections[empty_slot].txStopped = false;
  pthread_create(&connections[empty_slot].handler, NULL, handle_proxy_conn, (void*)&connections[empty_slot]);
  conn_m.unlock();
  return 0;
}

int proxy_server(char* listen_addr, unsigned short listen_port)
{
  int fd_lan_listen, fd_lan_accept;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage client_addr;
  socklen_t sin_size;
  struct sigaction sa;
  char s[INET6_ADDRSTRLEN];
  int yes = 1;
  int err;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  char port_str[5] = { 0 };
  snprintf(port_str, sizeof(port_str), "%d", listen_port);
  if ((err = getaddrinfo(listen_addr, port_str, &hints, &servinfo)) != 0) {
    LOG_DEBUG("getaddrinfo: %s", gai_strerror(err));
    return 1;
  }
  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((fd_lan_listen = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("socket");
      continue;
    }
    if (setsockopt(fd_lan_listen, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("setsockopt");
      exit(1);
    }
    if (bind(fd_lan_listen, p->ai_addr, p->ai_addrlen) == -1) {
      close(fd_lan_listen);
      perror("bind");
      continue;
    }
    break;
  }

  freeaddrinfo(servinfo);

  if (p == NULL) {
    LOG_DEBUG("failed to bind");
    exit(1);
  }

  if (listen(fd_lan_listen, LISTEN_BACKLOG) < 0) {
    perror("listen");
    exit(1);
  }

  char* zt_listen_addr = (char*)"0.0.0.0";

  LOG_INFO("Listening for connections via LAN on %s:%d", listen_addr, listen_port);
  LOG_INFO("Listening for connections via ZeroTier network on %s:%d", zt_listen_addr, listen_port);

  // Start listening on ZeroTier network using libzt

  int fd_zt_listen, fd_zt_accept;

  LOG_DEBUG("Creating socket...\n");
  if ((fd_zt_listen = zts_socket(ZTS_AF_INET, ZTS_SOCK_STREAM, 0)) < 0) {
    LOG_ERROR("Error (fd=%d, ret=%d, zts_errno=%d). Exiting.\n", fd_zt_listen, err, zts_errno);
    exit(1);
  }
  LOG_DEBUG("Binding...\n");
  if ((err = zts_bind(fd_zt_listen, zt_listen_addr, listen_port) < 0)) {
    LOG_ERROR("Error (fd=%d, ret=%d, zts_errno=%d). Exiting.\n", fd_zt_listen, err, zts_errno);
    exit(1);
  }
  LOG_DEBUG("Listening...\n");
  if ((err = zts_listen(fd_zt_listen, LISTEN_BACKLOG)) < 0) {
    LOG_ERROR("Error (fd=%d, ret=%d, zts_errno=%d). Exiting.\n", fd_zt_listen, err, zts_errno);
    exit(1);
  }

  // Set listen sockets to non blocking

  zts_set_blocking(fd_zt_listen, false);

  err = fcntl(fd_lan_listen, F_SETFL, fcntl(fd_lan_listen, F_GETFL, 0) | O_NONBLOCK);
  if (err == -1) {
    perror("calling fcntl");
    exit(0);
  }

  // Accept connections

  while (1) {
    sleep(1);
    LOG_DEBUG("Listening poll...");

    // Try to accept ZeroTier virtual network connections

    char remote_ipstr[ZTS_INET6_ADDRSTRLEN] = { 0 };
    unsigned short port = 0;
    if ((fd_zt_accept = zts_accept(fd_zt_listen, remote_ipstr, ZTS_INET6_ADDRSTRLEN, &port)) < 0) {
      // Nothing
    }
    else {
      LOG_INFO("Accepted connection from %s:%d\n", remote_ipstr, port);
      if (add_proxy_client_conn(fd_zt_accept, ConnectDirection::ToLocalAreaNetwork) < 0) {
        zts_close(fd_zt_accept);
      }
    }

    // Try to accept LAN connections

    sin_size = sizeof(client_addr);
    fd_lan_accept = accept(fd_lan_listen, (struct sockaddr*)&client_addr, &sin_size);
    if (fd_lan_accept == -1) {
      // Nothing
    }
    else {
      inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr*)&client_addr), s, sizeof(s));
      LOG_INFO("Accepted connection from %s", s);
      // TODO: Add port
      if (add_proxy_client_conn(fd_lan_accept, ConnectDirection::ToZeroTierNetwork) < 0) {
        close(fd_lan_accept);
      }
    }
  }
  return 0;
}

void* handle_proxy_conn(void* conn_ptr)
{
  struct proxy_connection* conn = (struct proxy_connection*)conn_ptr;
  if (! conn_ptr) {
    LOG_DEBUG("invalid connection object");
    return NULL;
  }

  if (conn->direction == ConnectDirection::ToZeroTierNetwork) {
    LOG_INFO("0x%p Connection request from LAN to ZeroTier network", (void*)conn);
  }
  if (conn->direction == ConnectDirection::ToLocalAreaNetwork) {
    LOG_INFO("0x%p Connection request from ZeroTier network to LAN", (void*)conn);
    zts_fused_socket(conn->fd_zan, conn);
  }

  bool _run = true;

  while (_run) {
    if (conn->fused_closed && conn->state == SOCKS_COMPLETE) {
      LOG_WARN("0x%p shutting down", conn);
      break;
    }

    usleep(SLEEP_INTERVAL);
    int rx_len_client = 0;
    int rx_len_resource = 0;
    char rx_from_client_buf[BUF_SIZE];
    char rx_from_zt_to_client_buf[BUF_SIZE];
    int nfds = 1;
    struct pollfd fds[2];
    memset(fds, 0, sizeof(fds));

    // Poll OS client socket, and OS socketpair end

    if (conn->direction == ConnectDirection::ToZeroTierNetwork) {
      fds[0].fd = conn->fd_lan;
      fds[0].events = POLLIN;
      LOG_DEBUG("0x%p poll (fd_lan:%2d)", conn, fds[0].fd);
      if (conn->state == SOCKS_COMPLETE) {
        fds[1].fd = conn->fd_zan;
        fds[1].events = POLLIN;
        nfds = 2;
        LOG_DEBUG("0x%p poll (fd_zan:%2d)", conn, fds[1].fd);
      }
      LOG_DEBUG("0x%p polling (%d) sockets", conn, nfds);
      int rc = poll(fds, nfds, POLL_TIMEOUT_MS);
      if (rc < 0) {
        LOG_ERROR("0x%p poll failed", conn);
        break;
      }
      if (rc == 0) {
        break;
      }
    }

    // Poll on OS socketpair end and LAN socket

    if (conn->direction == ConnectDirection::ToLocalAreaNetwork) {
      fds[0].fd = conn->fd_zan;
      fds[0].events = POLLIN;
      LOG_DEBUG("0x%p poll (fd_zan:%2d)", conn, fds[0].fd);
      if (conn->state == SOCKS_COMPLETE) {
        fds[1].fd = conn->fd_lan;
        fds[1].events = POLLIN;
        nfds = 2;
        LOG_DEBUG("0x%p poll (fd_lan:%2d)", conn, fds[1].fd);
      }
      int rc = poll(fds, nfds, POLL_TIMEOUT_MS);
      if (rc < 0) {
        LOG_ERROR("0x%p poll failed", conn);
        break;
      }
      if (rc == 0) {
        break;
      }
    }

    // Read data in preparation for forwarding

    for (int i = 0; i < nfds; i++) {
      if (fds[i].revents == 0) {
        continue;
      }
      if (fds[i].revents != POLLIN) {
        LOG_ERROR("0x%p != POLLIN (fd=%d)", conn, fds[i].fd);
        _run = false;
        break;
      }

      // Read data from client

      if ((fds[i].fd == conn->fd_lan && conn->direction == ConnectDirection::ToZeroTierNetwork) || (fds[i].fd == conn->fd_zan && conn->direction == ConnectDirection::ToLocalAreaNetwork)) {
        if (fds[i].fd == conn->fd_lan && conn->direction == ConnectDirection::ToZeroTierNetwork) {
          LOG_DEBUG("0x%p RX reading from client socket (OS:%d)", conn, conn->fd_lan);
          rx_len_client = read(conn->fd_lan, rx_from_client_buf, sizeof(rx_from_client_buf));
        }
        if (fds[i].fd == conn->fd_zan && conn->direction == ConnectDirection::ToLocalAreaNetwork) {
          LOG_DEBUG("0x%p RX reading from client socket (OS:%d)", conn, conn->fd_zan);
          rx_len_client = read(conn->fd_zan, rx_from_client_buf, sizeof(rx_from_client_buf));
        }
        if (rx_len_client < 0) {
          LOG_ERROR("0x%p RX read (%d) from client", conn, rx_len_client);
        }
        if (rx_len_client == 0) {
          // Closed connection
          LOG_DEBUG("0x%p RX read (%d) from client", conn, rx_len_client);
          _run = false;
          break;
        }
        if (rx_len_client > 0) {
          LOG_INFO("0x%p RX read (%d) from client", conn, rx_len_client);
        }
      }

      // Read data from resource

      if (conn->state == SOCKS_COMPLETE) {
        if ((fds[i].fd == conn->fd_zan && conn->direction == ConnectDirection::ToZeroTierNetwork) || (fds[i].fd == conn->fd_lan && conn->direction == ConnectDirection::ToLocalAreaNetwork)) {
          if (fds[i].fd == conn->fd_zan && conn->direction == ConnectDirection::ToZeroTierNetwork) {
            LOG_DEBUG("0x%p RX reading from resource socket (OS:%d)", conn, conn->fd_zan);
            rx_len_resource = read(conn->fd_zan, rx_from_zt_to_client_buf, sizeof(rx_from_zt_to_client_buf));
          }
          if (fds[i].fd == conn->fd_lan && conn->direction == ConnectDirection::ToLocalAreaNetwork) {
            LOG_DEBUG("0x%p RX reading from resource socket (OS:%d)", conn, conn->fd_lan);
            rx_len_resource = read(conn->fd_lan, rx_from_zt_to_client_buf, sizeof(rx_from_zt_to_client_buf));
          }
          if (rx_len_resource < 0) {
            LOG_ERROR("0x%p RX read (%d) from resource", conn, rx_len_resource);
            _run = false;
            break;
          }
          if (rx_len_resource > 0) {
            LOG_DEBUG("0x%p RX read (%d) from resource", conn, rx_len_resource);
          }
        }
      }
    }

    // General data forwarding

    if (conn->state == SOCKS_COMPLETE) {
      // Forward traffic from client to resource

      if (rx_len_client > 0) {
        int tx_len_to_resource = -1;
        if (conn->direction == ConnectDirection::ToZeroTierNetwork) {
          LOG_DEBUG("0x%p TX writing (%d) from client to resource (OS:%d)", conn, rx_len_client, conn->fd_zan);
          tx_len_to_resource = write(conn->fd_zan, rx_from_client_buf, rx_len_client);
        }
        if (conn->direction == ConnectDirection::ToLocalAreaNetwork) {
          LOG_DEBUG("0x%p TX writing (%d) from client to resource (OS:%d)", conn, rx_len_client, conn->fd_lan);
          tx_len_to_resource = write(conn->fd_lan, rx_from_client_buf, rx_len_client);
        }
        if (tx_len_to_resource < 0) {
          LOG_ERROR("0x%p TX wrote (%d) to resource", conn, tx_len_to_resource);
        }
        if (tx_len_to_resource > 0) {
          LOG_DEBUG("0x%p TX wrote (%d) to resource", conn, tx_len_to_resource);
        }
      }

      // Forward traffic from resource to client

      if (rx_len_resource > 0) {
        int tx_len_to_client = -1;
        if (conn->direction == ConnectDirection::ToZeroTierNetwork) {
          LOG_DEBUG("0x%p TX writing (%d) from resource to client (OS:%d)", conn, rx_len_resource, conn->fd_lan);
          tx_len_to_client = write(conn->fd_lan, rx_from_zt_to_client_buf, rx_len_resource);
        }
        if (conn->direction == ConnectDirection::ToLocalAreaNetwork) {
          LOG_DEBUG("0x%p TX writing (%d) from resource to client (ZT:%d)", conn, rx_len_resource, conn->fd_zan);
          tx_len_to_client = write(conn->fd_zan, rx_from_zt_to_client_buf, rx_len_resource);
        }
        if (tx_len_to_client < 0) {
          LOG_ERROR("0x%p TX wrote (%d) to client", conn, tx_len_to_client);
        }
        if (tx_len_to_client > 0) {
          LOG_DEBUG("0x%p TX wrote (%d) to client", conn, tx_len_to_client);
        }
      }
    }

    if (conn->state == SOCKS_OPEN) {
      // SOCKS_OPEN
      // +----+----------+----------+
      // |VER | NMETHODS | METHODS  |
      // +----+----------+----------+
      // | 1  |    1     | 1 to 255 |
      // +----+----------+----------+
      LOG_DEBUG("0x%p SOCKS_OPEN", conn);
      if (rx_len_client >= 3) {
        int version = rx_from_client_buf[SOCKS_IDX_VERSION];
        int methodsLength = rx_from_client_buf[IDX_NMETHODS];
        int firstSupportedMethod = rx_from_client_buf[IDX_METHODS];
        int supportedMethod = 0;
        if (firstSupportedMethod == 2) {
          supportedMethod = firstSupportedMethod;
        }
        LOG_DEBUG("0x%p  <ver=%d, meth_len=%d, supp_meth=%d>", conn, version, methodsLength, supportedMethod);

        // Send METHOD selection msg
        // +----+--------+
        // |VER | METHOD |
        // +----+--------+
        // | 1  |   1    |
        // +----+--------+
        char reply[2];
        reply[SOCKS_IDX_VERSION] = THIS_PROXY_VERSION;
        reply[IDX_METHOD] = supportedMethod;

        if (conn->direction == ConnectDirection::ToZeroTierNetwork) {
          send(conn->fd_lan, reply, sizeof(reply), 0);
        }
        if (conn->direction == ConnectDirection::ToLocalAreaNetwork) {
          send(conn->fd_zan, reply, sizeof(reply), 0);
        }
        conn->state = SOCKS_CONNECT_INIT;
        continue;
      }
    }

    if (conn->state == SOCKS_CONNECT_INIT) {
      // SOCKS_CONNECT_INIT
      // +----+-----+-------+------+----------+----------+
      // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
      // +----+-----+-------+------+----------+----------+
      // | 1  |  1  | X'00' |  1   | Variable |    2     |
      // +----+-----+-------+------+----------+----------+
      LOG_DEBUG("0x%p SOCKS_CONNECT_INIT", conn);
      // Ex. 4(meta) + 4(ipv4) + 2(port) = 10
      if (rx_len_client >= 10) {
        int version = rx_from_client_buf[SOCKS_IDX_VERSION];
        int cmd = rx_from_client_buf[IDX_COMMAND];
        int addr_type = rx_from_client_buf[IDX_ATYP];

        LOG_DEBUG("0x%p  <ver=%d, cmd=%d, typ=%d>", conn, version, cmd, addr_type);

        // CONNECT request
        if (cmd == 1) {
          LOG_DEBUG("0x%p cmd=%d", conn, cmd);
          // Ipv4
          if (addr_type == 1) {
            int raw_addr;
            memcpy(&raw_addr, &rx_from_client_buf[4], 4);
            char ipstr[16];
            inet_ntop(AF_INET, &raw_addr, (char*)ipstr, INET_ADDRSTRLEN);
            unsigned short port = 0;
            memcpy(&port, &rx_from_client_buf[8], 2);

            int err = -1;

            // Connect to resource on ZeroTier network

            if (conn->direction == ConnectDirection::ToZeroTierNetwork) {
              zts_fused_socket(INVALID_SOCKET_FD, conn);
              port = ntohs(port);
              LOG_DEBUG("0x%p connecting via zt to: %s:%d", conn, ipstr, port);
              err = zts_connect(conn->fd_zts, ipstr, port, CONNECT_TIMEOUT_S);
              LOG_DEBUG("0x%p conn->fd_zts=(ZT:%d)", conn, conn->fd_zts);
            }

            // Connect to resource on LAN

            if (conn->direction == ConnectDirection::ToLocalAreaNetwork) {
              LOG_DEBUG("0x%p connecting via lan to: %s:%d", conn, ipstr, ntohs(port));
              struct sockaddr_in in4;
              in4.sin_family = AF_INET;
              in4.sin_addr.s_addr = raw_addr;
              in4.sin_port = port;
              conn->fd_lan = socket(AF_INET, SOCK_STREAM, 0);
              err = connect(conn->fd_lan, (struct sockaddr*)&in4, sizeof(struct sockaddr));
              LOG_DEBUG("0x%p conn->fd_lan=(OS:%d)", conn, conn->fd_lan);
            }

            if (err < 0) {
              LOG_ERROR("0x%p error establishing connection to resource", conn);
              perror("");
              continue;
            }
            else {
              /*
                +----+-----+-------+------+----------+----------+
                |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                +----+-----+-------+------+----------+----------+
                | 1  |  1  | X'00' |  1   | Variable |    2     |
                +----+-----+-------+------+----------+----------+

              Where:

                o  VER    protocol version: X'05'
                o  REP    Reply field:
                o  X'00' succeeded
                o  X'01' general SOCKS server failure
                o  X'02' connection not allowed by ruleset
                o  X'03' Network unreachable
                o  X'04' Host unreachable
                o  X'05' Connection refused
                o  X'06' TTL expired
                o  X'07' Command not supported
                o  X'08' Address type not supported
                o  X'09' to X'FF' unassigned
                o  RSV    RESERVED
                o  ATYP   address type of following address
              */

              // REPLY
              conn->state = SOCKS_COMPLETE;
              char replybuf[REPLY_LEN] = { 0 };
              replybuf[0] = 5;   // ver
              replybuf[1] = 0;   // rep
              replybuf[2] = 0;   // rsv
              replybuf[3] = 1;   // address type

              memcpy(&replybuf[4], &raw_addr, 4);
              short bind_port = htonl(port);
              memcpy(&replybuf[8], &bind_port, 2);

              int reply_len = -1;
              if (conn->direction == ConnectDirection::ToZeroTierNetwork) {
                reply_len = send(conn->fd_lan, replybuf, REPLY_LEN, 0);
              }
              if (conn->direction == ConnectDirection::ToLocalAreaNetwork) {
                reply_len = send(conn->fd_zan, replybuf, REPLY_LEN, 0);
              }
              LOG_DEBUG("0x%p SOCKS Replying to client with (%d) bytes", conn, reply_len);
            }
          }
        }
      }
    }
  }
  LOG_INFO("0x%p Closing connection", conn);
  conn_m.lock();
  conn->shouldStop = true;
  conn->state = SOCKS_OPEN;
  LOG_WARN("0x%p waiting for IO threads to stop", conn);
  while (1) {
    usleep(SLEEP_INTERVAL);
    if (conn->txStopped && conn->rxStopped) {
      break;
    }
  }
  if (conn->direction == ConnectDirection::ToZeroTierNetwork) {
    close(conn->fd_lan);
  }
  if (conn->direction == ConnectDirection::ToLocalAreaNetwork) {
    close(conn->fd_zan);
  }
  conn_m.unlock();
  return NULL;
}

void on_zts_event(void* msgPtr)
{
  zts_event_msg_t* msg = (zts_event_msg_t*)msgPtr;
  if (msg->event_code == ZTS_EVENT_NODE_ONLINE) {
    LOG_DEBUG("ZTS_EVENT_NODE_ONLINE: %lx", msg->node->node_id);
  }
  if (msg->event_code == ZTS_EVENT_NODE_OFFLINE) {
    LOG_DEBUG("ZTS_EVENT_NODE_OFFLINE");
  }
  if (msg->event_code == ZTS_EVENT_NETWORK_NOT_FOUND) {
    LOG_DEBUG("ZTS_EVENT_NETWORK_NOT_FOUND: %lx", msg->network->net_id);
  }
  if (msg->event_code == ZTS_EVENT_NETWORK_ACCESS_DENIED) {
    LOG_DEBUG("ZTS_EVENT_NETWORK_ACCESS_DENIED: %lx", msg->network->net_id);
  }
  if (msg->event_code == ZTS_EVENT_ADDR_ADDED_IP4) {
    char ipstr[ZTS_INET6_ADDRSTRLEN] = { 0 };
    struct zts_sockaddr_in* in = (struct zts_sockaddr_in*)&(msg->addr->addr);
    zts_inet_ntop(ZTS_AF_INET, &(in->sin_addr), ipstr, ZTS_INET6_ADDRSTRLEN);
    LOG_DEBUG("ZTS_EVENT_ADDR_NEW_IP: %s", ipstr);
  }
}

using namespace ZeroTier;

/*
 * ZeroTier TCP Proxy Server
 *
 * This implements a simple packet encapsulation that is designed to look like
 * a TLS connection. It's not a TLS connection, but it sends TLS format record
 * headers. It could be extended in the future to implement a fake TLS
 * handshake.
 *
 * At the moment, each packet is just made to look like TLS application data:
 *   <[1] TLS content type> - currently 0x17 for "application data"
 *   <[1] TLS major version> - currently 0x03 for TLS 1.2
 *   <[1] TLS minor version> - currently 0x03 for TLS 1.2
 *   <[2] payload length> - 16-bit length of payload in bytes
 *   <[...] payload> - Message payload
 *
 * TCP is inherently inefficient for encapsulating Ethernet, since TCP and TCP
 * like protocols over TCP lead to double-ACKs. So this transport is only used
 * to enable access when UDP or other datagram protocols are not available.
 *
 * Clients send a greeting, which is a four-byte message that contains:
 *   <[1] ZeroTier major version>
 *   <[1] minor version>
 *   <[2] revision>
 *
 * If a client has sent a greeting, it uses the new version of this protocol
 * in which every encapsulated ZT packet is prepended by an IP address where
 * it should be forwarded (or where it came from for replies). This causes
 * this proxy to act as a remote UDP socket similar to a socks proxy, which
 * will allow us to move this function off the rootservers and onto dedicated
 * proxy nodes.
 *
 * Older ZT clients that do not send this message get their packets relayed
 * to/from 127.0.0.1:9993, which will allow them to talk to and relay via
 * the ZT node on the same machine as the proxy. We'll only support this for
 * as long as such nodes appear to be in the wild.
 */

struct TcpProxyService;

struct TcpProxyService {
  Phy<TcpProxyService*>* phy;
  int udpPortCounter;
  struct Client {
    char tcpReadBuf[131072];
    char tcpWriteBuf[131072];
    unsigned long tcpWritePtr;
    unsigned long tcpReadPtr;
    PhySocket* tcp;
    PhySocket* udp;
    time_t lastActivity;
    bool newVersion;
  };
  std::map<PhySocket*, Client> clients;

  PhySocket* getUnusedUdp(void* uptr)
  {
    for (int i = 0; i < 65535; ++i) {
      ++udpPortCounter;
      if (udpPortCounter > 0xfffe) {
        udpPortCounter = 1024;
      }
      struct sockaddr_in laddr;
      memset(&laddr, 0, sizeof(struct sockaddr_in));
      laddr.sin_family = AF_INET;
      laddr.sin_port = htons((uint16_t)udpPortCounter);
      PhySocket* udp = phy->udpBind(reinterpret_cast<struct sockaddr*>(&laddr), uptr);
      if (udp) {
        return udp;
      }
    }
    return (PhySocket*)0;
  }

  void phyOnDatagram(PhySocket* sock, void** uptr, const struct sockaddr* localAddr, const struct sockaddr* from, void* data, unsigned long len)
  {
    if (! *uptr) {
      return;
    }
    if ((from->sa_family == AF_INET) && (len >= 16) && (len < 2048)) {
      Client& c = *((Client*)*uptr);
      c.lastActivity = time((time_t*)0);

      unsigned long mlen = len;
      if (c.newVersion) {
        mlen += 7;	 // new clients get IP info
      }

      if ((c.tcpWritePtr + 5 + mlen) <= sizeof(c.tcpWriteBuf)) {
        if (! c.tcpWritePtr) {
          phy->setNotifyWritable(c.tcp, true);
        }

        c.tcpWriteBuf[c.tcpWritePtr++] = 0x17;	 // look like TLS data
        c.tcpWriteBuf[c.tcpWritePtr++] = 0x03;	 // look like TLS 1.2
        c.tcpWriteBuf[c.tcpWritePtr++] = 0x03;	 // look like TLS 1.2

        c.tcpWriteBuf[c.tcpWritePtr++] = (char)((mlen >> 8) & 0xff);
        c.tcpWriteBuf[c.tcpWritePtr++] = (char)(mlen & 0xff);

        if (c.newVersion) {
          c.tcpWriteBuf[c.tcpWritePtr++] = (char)4;	// IPv4
          *((uint32_t*)(c.tcpWriteBuf + c.tcpWritePtr)) = ((const struct sockaddr_in*)from)->sin_addr.s_addr;
          c.tcpWritePtr += 4;
          *((uint16_t*)(c.tcpWriteBuf + c.tcpWritePtr)) = ((const struct sockaddr_in*)from)->sin_port;
          c.tcpWritePtr += 2;
        }

        for (unsigned long i = 0; i < len; ++i) {
          c.tcpWriteBuf[c.tcpWritePtr++] = ((const char*)data)[i];
        }
      }

      printf("<< UDP %s:%d -> %.16llx\n", inet_ntoa(reinterpret_cast<const struct sockaddr_in*>(from)->sin_addr), (int)ntohs(reinterpret_cast<const struct sockaddr_in*>(from)->sin_port), (unsigned long long)&c);
    }
  }

  void phyOnTcpConnect(PhySocket* sock, void** uptr, bool success)
  {
    // unused, we don't initiate outbound connections
  }

  void phyOnTcpAccept(PhySocket* sockL, PhySocket* sockN, void** uptrL, void** uptrN, const struct sockaddr* from)
  {
    Client& c = clients[sockN];
    PhySocket* udp = getUnusedUdp((void*)&c);
    if (! udp) {
      phy->close(sockN);
      clients.erase(sockN);
      printf("** TCP rejected, no more UDP ports to assign\n");
      return;
    }
    c.tcpWritePtr = 0;
    c.tcpReadPtr = 0;
    c.tcp = sockN;
    c.udp = udp;
    c.lastActivity = time((time_t*)0);
    c.newVersion = false;
    *uptrN = (void*)&c;
    printf("<< TCP from %s -> %.16llx\n", inet_ntoa(reinterpret_cast<const struct sockaddr_in*>(from)->sin_addr), (unsigned long long)&c);
  }

  void phyOnTcpClose(PhySocket* sock, void** uptr)
  {
    if (! *uptr) {
      return;
    }
    Client& c = *((Client*)*uptr);
    phy->close(c.udp);
    clients.erase(sock);
    printf("** TCP %.16llx closed\n", (unsigned long long)*uptr);
  }

  void phyOnTcpData(PhySocket* sock, void** uptr, void* data, unsigned long len)
  {
    Client& c = *((Client*)*uptr);
    c.lastActivity = time((time_t*)0);

    for (unsigned long i = 0; i < len; ++i) {
      if (c.tcpReadPtr >= sizeof(c.tcpReadBuf)) {
        phy->close(sock);
        return;
      }
      c.tcpReadBuf[c.tcpReadPtr++] = ((const char*)data)[i];

      if (c.tcpReadPtr >= 5) {
        unsigned long mlen = (((((unsigned long)c.tcpReadBuf[3]) & 0xff) << 8) | (((unsigned long)c.tcpReadBuf[4]) & 0xff));
        if (c.tcpReadPtr >= (mlen + 5)) {
          if (mlen == 4) {
            // Right now just sending this means the client is 'new enough' for the IP header
            c.newVersion = true;
            printf("<< TCP %.16llx HELLO\n", (unsigned long long)*uptr);
          }
          else if (mlen >= 7) {
            char* payload = c.tcpReadBuf + 5;
            unsigned long payloadLen = mlen;

            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            if (c.newVersion) {
              if (*payload == (char)4) {
                // New clients tell us where their packets go.
                ++payload;
                dest.sin_family = AF_INET;
                dest.sin_addr.s_addr = *((uint32_t*)payload);
                payload += 4;
                dest.sin_port = *((uint16_t*)payload);	 // will be in network byte order already
                payload += 2;
                payloadLen -= 7;
              }
            }
            else {
              // For old clients we will just proxy everything to a local ZT instance. The
              // fact that this will come from 127.0.0.1 will in turn prevent that instance
              // from doing unite() with us. It'll just forward. There will not be many of
              // these.
              dest.sin_family = AF_INET;
              dest.sin_addr.s_addr = htonl(0x7f000001);	// 127.0.0.1
              dest.sin_port = htons(9993);
            }

            // Note: we do not relay to privileged ports... just an abuse prevention rule.
            if ((ntohs(dest.sin_port) > 1024) && (payloadLen >= 16)) {
              phy->udpSend(c.udp, (const struct sockaddr*)&dest, payload, payloadLen);
              printf(">> TCP %.16llx to %s:%d\n", (unsigned long long)*uptr, inet_ntoa(dest.sin_addr), (int)ntohs(dest.sin_port));
            }
          }

          memmove(c.tcpReadBuf, c.tcpReadBuf + (mlen + 5), c.tcpReadPtr -= (mlen + 5));
        }
      }
    }
  }

  void phyOnTcpWritable(PhySocket* sock, void** uptr)
  {
    Client& c = *((Client*)*uptr);
    if (c.tcpWritePtr) {
      long n = phy->streamSend(sock, c.tcpWriteBuf, c.tcpWritePtr);
      if (n > 0) {
        memmove(c.tcpWriteBuf, c.tcpWriteBuf + n, c.tcpWritePtr -= (unsigned long)n);
        if (! c.tcpWritePtr) {
          phy->setNotifyWritable(sock, false);
        }
      }
    }
    else {
      phy->setNotifyWritable(sock, false);
    }
  }

  void doHousekeeping()
  {
    std::vector<PhySocket*> toClose;
    time_t now = time((time_t*)0);
    for (std::map<PhySocket*, Client>::iterator c(clients.begin()); c != clients.end(); ++c) {
      if ((now - c->second.lastActivity) >= ZT_TCP_PROXY_CONNECTION_TIMEOUT_SECONDS) {
        toClose.push_back(c->first);
        toClose.push_back(c->second.udp);
      }
    }
    for (std::vector<PhySocket*>::iterator s(toClose.begin()); s != toClose.end(); ++s) {
      phy->close(*s);
    }
  }
};

int reflect(int argc, char** argv)
{
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  srand(time((time_t*)0));

  TcpProxyService svc;
  Phy<TcpProxyService*> phy(&svc, false, true);
  svc.phy = &phy;
  svc.udpPortCounter = 1023;

  {
    struct sockaddr_in laddr;
    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_port = htons(ZT_TCP_PROXY_TCP_PORT);
    if (! phy.tcpListen((const struct sockaddr*)&laddr)) {
      fprintf(stderr, "%s: fatal error: unable to bind TCP port %d\n", argv[0], ZT_TCP_PROXY_TCP_PORT);
      return 1;
    }
  }

  time_t lastDidHousekeeping = time((time_t*)0);
  for (;;) {
    phy.poll(120000);
    time_t now = time((time_t*)0);
    if ((now - lastDidHousekeeping) > 120) {
      lastDidHousekeeping = now;
      svc.doHousekeeping();
    }
  }

  return 0;
}

void emit_status_blob(const char* listen_addr, const int listen_port, uint64_t net_id)
{
  char config_str[1024] = { 0 };
  snprintf(
    config_str,
    sizeof(config_str),
    "{ \
 \n\t\"listen_addr\":%s, \
 \n\t\"listen_port\":%d, \
 \n\t\"node_id\":%lx, \
  \n\t\"net_id\":%lx \
\n}",
    listen_addr,
    listen_port,
    zts_node_get_id(),
    net_id);

  fprintf(stdout, "%s\n", config_str);
}

enum PylonMode { Invalid, PeerToPeer, Relayed };

int main(int argc, char** argv)
{
  if (argc == 2) {
    // In this mode, pylon will function as a network-agnostic TCP proxy for ZeroTier traffic
    if (strcmp(argv[1], "reflect")) {
      fprintf(stderr, "Invalid mode. Specify either [pylon reflect] or [pylon refract]\n");
      exit(0);
    }
    fprintf(stderr, "Relaying ZeroTier traffic on port %d\n", ZT_TCP_PROXY_TCP_PORT);
    reflect(argc, argv);
    exit(0);
  }

  PylonMode mode = PylonMode::Invalid;

  if (argc == 7) {
    // In this mode, pylon will proxy connections between the physical LAN and the ZeroTier virtual network
    if (strcmp(argv[1], "refract")) {
      fprintf(stderr, "Invalid mode. Specify either [pylon reflect] or [pylon refract]\n");
      exit(0);
    }
    if (strcmp(argv[3], "--listen-addr")) {
      fprintf(stderr, "Invalid configuration. Specify a local listening address with --listen-addr\n");
      exit(0);
    }
    if (strcmp(argv[5], "--listen-port")) {
      fprintf(stderr, "Invalid configuration. Specify a local listening port with --listen-port\n");
      exit(0);
    }
    mode = PylonMode::PeerToPeer;
    LOG_INFO("Running pylon instance in P2P mode");
  }
  if (argc == 11) {
    // In this mode, pylon will proxy connections between the physical LAN and the ZeroTier virtual network (via a relay)
    if (strcmp(argv[1], "refract")) {
      fprintf(stderr, "Invalid mode. Specify either [pylon reflect] or [pylon refract]\n");
      exit(0);
    }
    if (strcmp(argv[3], "--listen-addr")) {
      fprintf(stderr, "Invalid configuration. Specify a local listening address with --listen-addr\n");
      exit(0);
    }
    if (strcmp(argv[5], "--listen-port")) {
      fprintf(stderr, "Invalid configuration. Specify a local listening port with --listen-port\n");
      exit(0);
    }
    if (strcmp(argv[7], "--relay-addr")) {
      fprintf(stderr, "Invalid configuration. Specify a relay address with --relay-addr\n");
      exit(0);
    }
    if (strcmp(argv[9], "--relay-port")) {
      fprintf(stderr, "Invalid configuration. Specify a relay port with --relay-port\n");
      exit(0);
    }
    mode = PylonMode::Relayed;
    LOG_INFO("Running pylon instance in RELAYED mode (a [pylon reflect] instance is also required)");
  }

  if (mode == PylonMode::Invalid) {
    fprintf(stderr, "\nUsage:\n\n");
    fprintf(stderr, "pylon refract <net_id> --listen-addr 0.0.0.0 --listen-port 1080 --relay-addr 1.2.3.4 --relay-port 443\n");
    exit(0);
  }

  long long int net_id = strtoull(argv[2], NULL, 16);
  char* listen_addr = argv[4];
  unsigned int listen_port = atoi(argv[6]);

  const char* env_secret_key = getenv("ZT_PYLON_SECRET_KEY");
  const char* env_whitelisted_port = getenv("ZT_PYLON_WHITELISTED_PORT");

  if (! env_secret_key) {
    LOG_ERROR("No secret key provided. Set ZT_PYLON_SECRET_KEY");
    exit(0);
  }

  // Determine which port ZeroTier should use for UDP transport (if any at all)

  if (env_whitelisted_port) {
    if (mode == PylonMode::Relayed) {
      LOG_WARN("Whitelisted UDP port was specified but relay mode will ignore it and only use TCP/443");
    }
    else {
      LOG_INFO("ZT_PYLON_WHITELISTED_PORT set, using UDP/%s for ZeroTier transport", env_whitelisted_port);
      if (zts_init_set_port(atoi(env_whitelisted_port)) < ZTS_ERR_OK) {
        LOG_ERROR("Failed to set ZeroTier transport port. Exiting.");
        exit(0);
      }
    }
  }
  else {
    if (mode == PylonMode::PeerToPeer) {
      LOG_WARN("No udp port set, picking random");
      zts_init_set_port(0);
    }
  }

  // Initialize node

  int err = ZTS_ERR_OK;

  zts_init_set_event_handler(&on_zts_event);

  char* tcp_relay_addr = (char*)"0.0.0.0";
  unsigned short tcp_relay_port = 443;

  if (mode == PylonMode::Relayed) {
    LOG_WARN("Configuring Pylon to use relay: %s:%d", tcp_relay_addr, tcp_relay_port);
    zts_init_allow_tcp_relay(1);
    zts_init_force_tcp_relay(1);
    zts_init_set_tcp_relay(tcp_relay_addr, tcp_relay_port);
  }

  if ((err = zts_init_from_memory(env_secret_key, strlen(env_secret_key))) != ZTS_ERR_OK) {
    LOG_ERROR("Failed to start zt node. Contents of ZT_PYLON_SECRET_KEY may be invalid, error = %d. Exiting.", err);
    exit(1);
  }

  // Start node

  if ((err = zts_node_start()) != ZTS_ERR_OK) {
    LOG_ERROR("Failed to start zt node, error = %d. Exiting.", err);
    exit(1);
  }

  LOG_INFO("Waiting for zt node to come online...");
  while (! zts_node_is_online()) {
    zts_util_delay(25);
  }

  // LOG_DEBUG("zt port = %d", zts_node_get_port());
  LOG_INFO("zt node: %lx", zts_node_get_id());

  // Join network

  LOG_INFO("Joining network %llx ... (please authorize)", net_id);
  if (zts_net_join(net_id) != ZTS_ERR_OK) {
    LOG_DEBUG("Failed to join network. Exiting.");
    exit(1);
  }
  LOG_INFO("Waiting for network join to complete");
  while (! zts_net_transport_is_ready(net_id)) {
    zts_util_delay(25);
  }
  int family = zts_util_get_ip_family(listen_addr);
  LOG_INFO("Waiting for address assignment from network...");
  while (! (zts_addr_is_assigned(net_id, family))) {
    zts_util_delay(25);
  }
  char ipstr[ZTS_IP_MAX_STR_LEN] = { 0 };
  zts_addr_get_str(net_id, family, ipstr, ZTS_IP_MAX_STR_LEN);
  LOG_INFO("Address on network %llx is %s", net_id, ipstr);

  emit_status_blob(listen_addr, listen_port, net_id);

  proxy_server(listen_addr, listen_port);

  return zts_node_stop();
}
