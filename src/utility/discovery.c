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

#include "kinetic_client.h"
#include "kinetic_types.h"
#include "byte_array.h"
#include "socket99.h"
#include "json.h"

#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <time.h>

#include <netinet/in.h>

#include <openssl/sha.h>

enum {
    DRIVE_STATE_UNKNWN,
    DRIVE_STATE_LOCKED,
    DRIVE_STATE_CVMISS,
    DRIVE_STATE_WARNING,
    DRIVE_STATE_OFFLINE,
    DRIVE_STATE_TIMEOUT,
    DRIVE_STATE_ONLINE,
    DRIVE_STATE_BOOTPC,
    DRIVE_STATE_SIZE
};

struct _Interface {
    char name[50];            /* Name of interface, i.e. eth0 */
    char  ip4[50];            /* IPv4 Address */
    char  ip6[50];            /* IPv6 Address */
    char  eth[50];            /* Ethernet Address */
};

typedef struct _Interface  Interfaces;

struct _DriveEntry {

    char    wwname[50];       /* World Wide Name */
    char     fwver[50];       /* Firmware Version */
    char     maker[50];       /* Manufacturer */
    char     model[50];       /* Model */
    char     serno[50];       /* Drive Serial Number */
    char proto_ver[50];       /* Protobuf Protocol Version */

    Interfaces interfaces[2]; /* only two interfaces for now */

    int mcast_port;           /* Default 8123 */
    int tls_port;             /* Default 8443 */

    uint8_t state;            /* Current record state */
    struct timeval tstamp;    /* Time Stamp */
};

typedef struct _DriveEntry DriveEntries;

struct _EntryArray {
    uint32_t      allocated;  /* Amount allocated */
    uint32_t      used;       /* Amount used */
    DriveEntries **entries;   /* Drive Entries */
};

typedef struct _EntryArray EntryArray;

static int   discover_service(char *host, int port);
static bool  find_drive_entry(struct timeval t, const char *id);
static char *trim_json_string(char *str);
static int   getDriveState(char *host, int port);
void         print_drive_entry(DriveEntries *drv, int state);

EntryArray *driveList = NULL;

//------------------------------------------------------------------------------
// Main Entry Point Definition
int main(int argc, char** argv)
{

    char *default_host = "239.1.2.3";
    int   default_port = KINETIC_PORT;

    char *host = NULL;
    int   port = 0;

/*
    int option, optionIndex = 0;

    struct option long_options[] = {
     
    };

    while ((option = getopt_long_only(argc, argv, "?lhptics:", long_options, &optionIndex)) != -1) {
    }
*/

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

static int getDriveState(char *host, int port) {

    int retval = DRIVE_STATE_UNKNWN;

    KineticSession *session;

    KineticClientConfig clientConfig;

    clientConfig.logFile              = "stdout";
    clientConfig.logLevel             = 0;
    clientConfig.readerThreads        = 0;
    clientConfig.maxThreadpoolThreads = 0;

    KineticClient *client = KineticClient_Init(&clientConfig);

    if(client != NULL) {
        const char HmacKeyString[]   = "asdfasdf";

        KineticSessionConfig sessionConfig;

        strncpy(sessionConfig.host, host, HOST_NAME_MAX);


        sessionConfig.clusterVersion = 0; // TODO: How do we determine clusterversion?
        sessionConfig.identity       = 1;
        sessionConfig.useSsl         = true;
        sessionConfig.port           = (sessionConfig.useSsl == true) ? 8443 : port;
        sessionConfig.timeoutSeconds = 1;
        sessionConfig.hmacKey        = ByteArray_CreateWithCString(HmacKeyString);

        KineticStatus session_status = KineticClient_CreateSession(&sessionConfig, client, &session);

        if(session_status == KINETIC_STATUS_SUCCESS) {
            retval = DRIVE_STATE_ONLINE;

            KineticStatus noop_status = KineticClient_NoOp(session);

            if(noop_status != KINETIC_STATUS_SUCCESS) {

                KineticStatus termi_status = KineticClient_GetTerminationStatus(session);

                if(termi_status == KINETIC_STATUS_DEVICE_LOCKED) {
                    printf("Got KINETIC_STATUS_DEVICE_LOCKED\n");
                    retval = DRIVE_STATE_LOCKED;
                } else if(termi_status == KINETIC_STATUS_INVALID_REQUEST) {
                    // 3.0.0 drives report INVALID_REQUEST instead of DEVICE_LOCKED
                    retval = DRIVE_STATE_LOCKED;
                }

                if(noop_status == KINETIC_STATUS_CLUSTER_MISMATCH) {
                    retval = DRIVE_STATE_CVMISS;
                }
            }

        } else {
            printf("%s:%d %s\n", __FILE__, __LINE__, Kinetic_GetStatusDescription(session_status));
        }

        // Clean up
        KineticClient_DestroySession(session);
        KineticClient_Shutdown(client);
    }

    return retval;
}

static char *trim_json_string(char *str) {
    int i = 0;
    int j = strlen(str) - 1;
    int k = 0;

    while(str[i] == '"' && str[i] != '\0') i++;
    while(str[j] == '"' && j > 0) j--;
    while(i <= j) str[k++] = str[i++];

    str[k] = '\0';

    return str;
}

void print_drive_entry(DriveEntries *drv, int state) {

    time_t epoch       = time(NULL);
    struct tm timetag  = *localtime(&epoch);

    char time_str[20]  = "";

    char eth1_str[255] = "";
    char eth0_str[255] = "";

    char state_str[15] = "";

    char proto_str[50] = "";

    snprintf(time_str, 20, "%04d-%03d-%02d:%02d:%02d", timetag.tm_year + 1900, timetag.tm_yday, timetag.tm_hour, timetag.tm_min, timetag.tm_sec);

    switch(state) {
        case DRIVE_STATE_UNKNWN: {
            strncpy(state_str, "UNKNWN", 15); 
            break;
        }

        case DRIVE_STATE_LOCKED: {
            strncpy(proto_str, drv->proto_ver, 15);

            snprintf(eth0_str, 255, "%s %s %s %s", drv->interfaces[0].name, drv->interfaces[0].ip4, drv->interfaces[0].ip6, drv->interfaces[0].eth);
            snprintf(eth1_str, 255, "%s %s %s %s", drv->interfaces[1].name, drv->interfaces[1].ip4, drv->interfaces[1].ip6, drv->interfaces[1].eth);

            strncpy(state_str, "LOCKED", 15); 
            break;
        }

        case DRIVE_STATE_CVMISS: {
            strncpy(proto_str, drv->proto_ver, 15);

            snprintf(eth0_str, 255, "%s %s %s %s", drv->interfaces[0].name, drv->interfaces[0].ip4, drv->interfaces[0].ip6, drv->interfaces[0].eth);
            snprintf(eth1_str, 255, "%s %s %s %s", drv->interfaces[1].name, drv->interfaces[1].ip4, drv->interfaces[1].ip6, drv->interfaces[1].eth);

            strncpy(state_str, "CV-MISMATCH", 15); 
            break;
        }

        case DRIVE_STATE_WARNING: {
            strncpy(proto_str, drv->proto_ver, 15);

            snprintf(eth0_str, 255, "%s %s %s %s", drv->interfaces[0].name, drv->interfaces[0].ip4, drv->interfaces[0].ip6, drv->interfaces[0].eth);
            snprintf(eth1_str, 255, "%s %s %s %s", drv->interfaces[1].name, drv->interfaces[1].ip4, drv->interfaces[1].ip6, drv->interfaces[1].eth);

            strncpy(state_str, "WARNING", 15); 
            break;
        }

        case DRIVE_STATE_OFFLINE: {
            strncpy(proto_str, drv->proto_ver, 15);

            snprintf(eth0_str, 255, "%s %s %s %s", drv->interfaces[0].name, drv->interfaces[0].ip4, drv->interfaces[0].ip6, drv->interfaces[0].eth);
            snprintf(eth1_str, 255, "%s %s %s %s", drv->interfaces[1].name, drv->interfaces[1].ip4, drv->interfaces[1].ip6, drv->interfaces[1].eth);

            strncpy(state_str, "OFFLINE", 15); 
            break;
        }

        case DRIVE_STATE_TIMEOUT: {
            strncpy(proto_str, drv->proto_ver, 15);

            snprintf(eth0_str, 255, "%s %s %s %s", drv->interfaces[0].name, drv->interfaces[0].ip4, drv->interfaces[0].ip6, drv->interfaces[0].eth);
            snprintf(eth1_str, 255, "%s %s %s %s", drv->interfaces[1].name, drv->interfaces[1].ip4, drv->interfaces[1].ip6, drv->interfaces[1].eth);

            strncpy(state_str, "TIMEOUT", 15); 
            break;
        }

        case DRIVE_STATE_ONLINE: {
            strncpy(proto_str, drv->proto_ver, 15);

            snprintf(eth0_str, 255, "%s %s %s %s", drv->interfaces[0].name, drv->interfaces[0].ip4, drv->interfaces[0].ip6, drv->interfaces[0].eth);
            snprintf(eth1_str, 255, "%s %s %s %s", drv->interfaces[1].name, drv->interfaces[1].ip4, drv->interfaces[1].ip6, drv->interfaces[1].eth);

            strncpy(state_str, "ONLINE", 15); 
            break;
        }

        case DRIVE_STATE_BOOTPC: {
            strncpy(state_str, "BOOTPC", 15); 
            break;
        }

        default: {
            strncpy(state_str, "UNKNWN", 15); 
            break;
        }
    }

    printf("%s,%s,%s,%s,%d,%d,%s,%s\n", time_str, state_str, drv->serno, drv->proto_ver, drv->mcast_port, drv->tls_port, eth0_str, eth1_str);
}

static bool find_drive_entry(struct timeval t, const char *id) {
    bool flag = FALSE;

    uint32_t i = 0;

    for(i = 0; i < driveList->used; i++) {

        if(strlen((driveList->entries[i])->wwname) != strlen(id)) continue;

        if(strstr((driveList->entries[i])->wwname, id)) {
            flag = TRUE;

            /* stamp the entry */
            (driveList->entries[i])->tstamp.tv_sec  = t.tv_sec;
            (driveList->entries[i])->tstamp.tv_usec = t.tv_usec;

            // Check for a state change.
            // TODO: let's not assume iface[0] has a valid IP address.
            int s = getDriveState((driveList->entries[i])->interfaces[0].ip4, (driveList->entries[i])->mcast_port);

            if(s != (driveList->entries[i])->state) {
                (driveList->entries[i])->state = s;
                print_drive_entry(driveList->entries[i], (driveList->entries[i])->state);
            }

            break;
        }
    }

    return flag;
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

    driveList = (EntryArray *)malloc(sizeof(EntryArray));

    driveList->used       = 0;
    driveList->allocated  = 500;
    driveList->entries    = NULL;

    driveList->entries    = (DriveEntries **)malloc(500 * sizeof(DriveEntries));

    // TODO: Test memory allocation!

    for (;;) {
        ssize_t received = recvfrom(res.fd, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &addr_len);

        struct timeval arrival_time;

        char json_str[50] = "";

        if (received > 0) {

            struct json_object  *obj = NULL;
            struct json_object  *val = NULL;
            struct json_tokener *tok = NULL;

            tok = json_tokener_new();

            buf[received] = '\0';

            obj = json_tokener_parse_ex(tok, buf, received);

            gettimeofday(&arrival_time, NULL);

            if(obj == NULL) {
                if(json_tokener_get_error(tok) != json_tokener_error_parse_eof) {
                    printf("JSON error %d", json_tokener_get_error(tok));
                }
            }

            if(driveList->used == driveList->allocated) {
                driveList->entries    = realloc(driveList->entries, (driveList->used + 500) * sizeof(DriveEntries *));
                driveList->allocated += 500;
            }

            if(json_object_object_get_ex(obj, "world_wide_name", &val)) {

                strncpy(json_str, json_object_to_json_string(val), 50);
                char *s_ptr = trim_json_string(json_str);

                if(!find_drive_entry(arrival_time, s_ptr)) {
                    DriveEntries *new_entry = (DriveEntries *)malloc(sizeof(DriveEntries));

                    // TODO: Test memory allocation!

                    /* Default Values */
                    strncpy(new_entry->wwname, s_ptr, 50);

                    new_entry->mcast_port = 0;
                    new_entry->tls_port   = 0;
                    new_entry->state      = DRIVE_STATE_ONLINE;

                    if(json_object_object_get_ex(obj, "firmware_version", &val)) {
                        strncpy(json_str, json_object_to_json_string(val), 50);
                        s_ptr = trim_json_string(json_str);

                        strncpy(new_entry->fwver, s_ptr, 50);
                    }

                    if(json_object_object_get_ex(obj, "manufacturer", &val)) {
                        strncpy(json_str, json_object_to_json_string(val), 50);
                        s_ptr = trim_json_string(json_str);

                        strncpy(new_entry->maker, s_ptr, 50);
                    }

                    if(json_object_object_get_ex(obj, "model", &val)) {
                        strncpy(json_str, json_object_to_json_string(val), 50);
                        s_ptr = trim_json_string(json_str);

                        strncpy(new_entry->model, s_ptr, 50);
                    }

                    if(json_object_object_get_ex(obj, "serial_number", &val)) {
                        strncpy(json_str, json_object_to_json_string(val), 50);
                        s_ptr = trim_json_string(json_str);

                        strncpy(new_entry->serno, s_ptr, 50);
                    }

                    if(json_object_object_get_ex(obj, "protocol_version", &val)) {
                        strncpy(json_str, json_object_to_json_string(val), 50);
                        s_ptr = trim_json_string(json_str);

                        strncpy(new_entry->proto_ver, s_ptr, 50);
                    }

                    if(json_object_object_get_ex(obj, "port", &val)) {
                        strncpy(json_str, json_object_to_json_string(val), 50);

                        new_entry->mcast_port = atoi(json_str);
                    }

                    if(json_object_object_get_ex(obj, "tlsPort", &val)) {
                        strncpy(json_str, json_object_to_json_string(val), 50);

                        new_entry->tls_port = atoi(json_str);
                    }

                    if(json_object_object_get_ex(obj, "network_interfaces", &val)) {
                        int i = 0;

                        // int len = json_object_array_length(val);

                        struct json_object *array_obj = NULL;
                        struct json_object *array_val = NULL;

                        /* Currently the data structure only supports two interfaces */
                        for(i = 0; i < 2; i++) {
                            array_obj = json_object_array_get_idx(val, i);

                            if(json_object_object_get_ex(array_obj, "name", &array_val)) {
                                strncpy(json_str, json_object_to_json_string(array_val), 50);
                                s_ptr = trim_json_string(json_str);

                                strncpy(new_entry->interfaces[i].name, s_ptr, 50);
                            }

                            if(json_object_object_get_ex(array_obj, "ipv4_addr", &array_val)) {
                                strncpy(json_str, json_object_to_json_string(array_val), 50);
                                s_ptr = trim_json_string(json_str);

                                strncpy(new_entry->interfaces[i].ip4, s_ptr, 50);

                                new_entry->state      = getDriveState(s_ptr, new_entry->mcast_port);
                            }

                            if(json_object_object_get_ex(array_obj, "ipv6_addr", &array_val)) {
                                strncpy(json_str, json_object_to_json_string(array_val), 50);
                                s_ptr = trim_json_string(json_str);

                                strncpy(new_entry->interfaces[i].ip6, s_ptr, 50);

                                //
                                // KineticClient_CreateSession() doesn't seem to like ipv6 addresses.
                                //
                                /* new_entry->state      = getDriveState(s_ptr, new_entry->mcast_port); */
                            }

                            if(json_object_object_get_ex(array_obj, "mac_addr", &array_val)) {
                                strncpy(json_str, json_object_to_json_string(array_val), 50);
                                s_ptr = trim_json_string(json_str);

                                strncpy(new_entry->interfaces[i].eth, s_ptr, 50);
                            }

                            json_object_put(array_obj);
                        }
                    }

                    driveList->entries[driveList->used] = new_entry;
                    driveList->used++;

                    print_drive_entry(new_entry, new_entry->state);
                }

            }

            json_object_put(obj);
        }
    }

    return 0;
}
