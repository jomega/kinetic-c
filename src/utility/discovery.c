/*
* kinetic-c
* Copyright (C) 2015 Seagate Technology.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*
*/

#define _GNU_SOURCE

#include <stdio.h>

#include <err.h>
#include <errno.h>

#include <netinet/in.h>

#include "kinetic_client.h"
#include "socket99.h"
#include "json.h"

static int discover_service(char *host, int port);


//------------------------------------------------------------------------------
// Main Entry Point Definition
int main(int argc, char** argv)
{

    char *default_host = "239.1.2.3";
    int   default_port = KINETIC_PORT;

    char *host = NULL;
    int   port = 0;

    // TODO: CLI args?

    switch(argc) {
      case 3: {
        host = argv[1];
        port = atoi(argv[2]);
        break;
      }

      case 1: {
        host = default_host;
        port = default_port;
        break;
      }

      default: {
        // TODO: usage();
        break;
      }
    }

    return discover_service(host, port);
}
 
   
//------------------------------------------------------------------------------
// Service discovery

static int discover_service(char *host, int port) {

    struct in_addr mcastAddr;
    struct ip_mreq mreq;

    struct hostent *host_struct;

    int v_true = 1;
    socket99_config cfg = {
        .host = INADDR_ANY,
        .port = port,
        .server = true,
        .datagram = true,
        .sockopts = {
            {/*SOL_SOCKET,*/ SO_BROADCAST, &v_true, sizeof(v_true)},
        },
    };
    socket99_result res;

    if (!socket99_open(&cfg, &res)) {
        errno = res.saved_errno;
        printf("res %d, %d\n", res.status, res.getaddrinfo_error);
        if (res.status == SOCKET99_ERROR_GETADDRINFO) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res.getaddrinfo_error));
            return 1;
        }
        err(1, "socket99_open");
        return 1;
    }

    if((host_struct = gethostbyname(host)) == NULL) {
        err(1, "gethostbyname");
        // usage();
    }

    memcpy(&mcastAddr, host_struct->h_addr_list[0], host_struct->h_length);

    if(!IN_MULTICAST(ntohl(mcastAddr.s_addr))) {
        err(1, "invalid mcast address");
        // usage();
    }

    mreq.imr_multiaddr.s_addr = mcastAddr.s_addr;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (0 != setsockopt(res.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq))) {
        err(1, "failed to join multicast group");
        // usage();
    }

    char buf[1024];
    struct sockaddr_storage client_addr;
    socklen_t addr_len = sizeof(client_addr);

    /* TODO:
     *     + nonblocking, with max timeout
     *     + set up multicast on 239.1.2.3
     *     + if we receive any info, print it */

    for (;;) {
        ssize_t received = recvfrom(res.fd, buf, sizeof(buf), 0,
            (struct sockaddr *)&client_addr, &addr_len);

        if (received > 0) {
            buf[received] = '\0';
            printf("Got: '%s'\n", buf);
            /* TODO: sink into json, print decoded data. */
        }
    }
    
    return 0;
}
