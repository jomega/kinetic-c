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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>
#include <err.h>
#include <time.h>

#include "bus_internal_types.h"
#include "listener.h"
#include "listener_helper.h"
#include "listener_cmd.h"
#include "listener_task.h"
#include "listener_internal.h"
#include "syscall.h"
#include "util.h"

struct listener *listener_init(struct bus *b, struct bus_config *cfg) {
    struct listener *l = calloc(1, sizeof(*l));
    if (l == NULL) { return NULL; }

    assert(b);
    l->bus = b;
    BUS_LOG(b, 2, LOG_LISTENER, "init", b->udata);

    int pipes[2];
    if (0 != pipe(pipes)) {
        free(l);
        return NULL;
    }

    l->commit_pipe = pipes[1];
    l->incoming_msg_pipe = pipes[0];
    l->fds[INCOMING_MSG_PIPE_ID].fd = l->incoming_msg_pipe;
    l->fds[INCOMING_MSG_PIPE_ID].events = POLLIN;
    l->shutdown_notify_fd = LISTENER_NO_FD;

    for (int i = MAX_PENDING_MESSAGES - 1; i >= 0; i--) {
        rx_info_t *info = &l->rx_info[i];
        info->state = RIS_INACTIVE;

        uint16_t *p_id = (uint16_t *)&info->id;
        info->next = l->rx_info_freelist;
        l->rx_info_freelist = info;
        *p_id = i;
    }

    for (int pipe_count = 0; pipe_count < MAX_QUEUE_MESSAGES; pipe_count++) {
        listener_msg *msg = &l->msgs[pipe_count];
        uint8_t *p_id = (uint8_t *)&msg->id;
        *p_id = pipe_count;  /* Set (const) ID. */

        if (0 != pipe(msg->pipes)) {
            for (int i = 0; i < pipe_count; i++) {
                msg = &l->msgs[i];
                syscall_close(msg->pipes[0]);
                syscall_close(msg->pipes[1]);
            }
            syscall_close(l->commit_pipe);
            syscall_close(l->incoming_msg_pipe);
            free(l);
            return NULL;
        }
        msg->next = l->msg_freelist;
        l->msg_freelist = msg;
    }
    l->rx_info_max_used = 0;

    (void)cfg;
    return l;
}

bool listener_add_socket(struct listener *l,
        connection_info *ci, int *notify_fd) {
    listener_msg *msg = listener_helper_get_free_msg(l);
    if (msg == NULL) { return false; }

    msg->type = MSG_ADD_SOCKET;
    msg->u.add_socket.info = ci;
    msg->u.add_socket.notify_fd = msg->pipes[1];
    return listener_helper_push_message(l, msg, notify_fd);
}

bool listener_remove_socket(struct listener *l, int fd, int *notify_fd) {
    listener_msg *msg = listener_helper_get_free_msg(l);
    if (msg == NULL) { return false; }

    msg->type = MSG_REMOVE_SOCKET;
    msg->u.remove_socket.fd = fd;
    msg->u.remove_socket.notify_fd = msg->pipes[1];
    return listener_helper_push_message(l, msg, notify_fd);
}

bool listener_hold_response(struct listener *l, int fd,
        int64_t seq_id, int16_t timeout_sec, int *notify_fd) {
    listener_msg *msg = listener_helper_get_free_msg(l);
    struct bus *b = l->bus;
    if (msg == NULL) {
        BUS_LOG(b, 1, LOG_LISTENER, "OUT OF MESSAGES", b->udata);
        return false;
    }

    BUS_LOG_SNPRINTF(b, 5, LOG_MEMORY, b->udata, 128,
        "listener_hold_response with <fd:%d, seq_id:%lld>",
        fd, (long long)seq_id);

    msg->type = MSG_HOLD_RESPONSE;
    msg->u.hold.fd = fd;
    msg->u.hold.seq_id = seq_id;
    msg->u.hold.timeout_sec = timeout_sec;
    msg->u.hold.notify_fd = msg->pipes[1];

    bool pm_res = listener_helper_push_message(l, msg, notify_fd);
    if (!pm_res) {
        BUS_LOG_SNPRINTF(b, 0, LOG_MEMORY, b->udata, 128,
            "listener_hold_response with <fd:%d, seq_id:%lld> FAILED",
            fd, (long long)seq_id);
    }
    return pm_res;
}

bool listener_expect_response(struct listener *l, boxed_msg *box,
        uint16_t *backpressure) {
    listener_msg *msg = listener_helper_get_free_msg(l);
    struct bus *b = l->bus;
    if (msg == NULL) {
        BUS_LOG_SNPRINTF(b, 0, LOG_MEMORY, b->udata, 128,
            "! listener_helper_get_free_msg fail %p", (void*)box);
        return false;
    }

    BUS_LOG_SNPRINTF(b, 3, LOG_MEMORY, b->udata, 128,
        "listener_expect_response with box of %p, seq_id:%lld",
        (void*)box, (long long)box->out_seq_id);

    msg->type = MSG_EXPECT_RESPONSE;
    msg->u.expect.box = box;
    *backpressure = ListenerTask_GetBackpressure(l);
    BUS_ASSERT(b, b->udata, box->result.status != BUS_SEND_UNDEFINED);

    bool pm = listener_helper_push_message(l, msg, NULL);
    if (!pm) {
        BUS_LOG_SNPRINTF(b, 0, LOG_MEMORY, b->udata, 128,
            "! listener_helper_push_message fail %p", (void*)box);
    }
    return pm;
}

bool listener_shutdown(struct listener *l, int *notify_fd) {
    listener_msg *msg = listener_helper_get_free_msg(l);
    if (msg == NULL) { return false; }

    msg->type = MSG_SHUTDOWN;
    msg->u.shutdown.notify_fd = msg->pipes[1];
    return listener_helper_push_message(l, msg, notify_fd);
}

void listener_free(struct listener *l) {
    if (l) {
        struct bus *b = l->bus;
        /* Thread has joined but data has not been freed yet. */
        assert(l->shutdown_notify_fd == LISTENER_SHUTDOWN_COMPLETE_FD);
        for (int i = 0; i < MAX_PENDING_MESSAGES; i++) {
            rx_info_t *info = &l->rx_info[i];

            switch (info->state) {
            case RIS_INACTIVE:
                break;
            case RIS_HOLD:
                break;
            case RIS_EXPECT:
                if (info->u.expect.box) {
                    /* TODO: This can leak memory, since the caller's
                     * callback is not being called. It should be called
                     * with BUS_SEND_RX_FAILURE, if it's safe to do so. */
                    free(info->u.expect.box);
                    info->u.expect.box = NULL;
                }
                break;
            default:
                BUS_LOG_SNPRINTF(b, 0, LOG_LISTENER, b->udata, 64,
                    "match fail %d on line %d", info->state, __LINE__);
                BUS_ASSERT(b, b->udata, false);
            }
        }

        for (int i = 0; i < MAX_QUEUE_MESSAGES; i++) {
            listener_msg *msg = &l->msgs[i];
            switch (msg->type) {
            case MSG_ADD_SOCKET:
                ListenerCmd_NotifyCaller(l, msg->u.add_socket.notify_fd);
                break;
            case MSG_REMOVE_SOCKET:
                ListenerCmd_NotifyCaller(l, msg->u.remove_socket.notify_fd);
                break;
            case MSG_EXPECT_RESPONSE:
                if (msg->u.expect.box) { free(msg->u.expect.box); }
                break;
            default:
                break;
            }

            syscall_close(msg->pipes[0]);
            syscall_close(msg->pipes[1]);
        }

        if (l->read_buf) {
            free(l->read_buf);
        }                

        syscall_close(l->commit_pipe);
        syscall_close(l->incoming_msg_pipe);

        free(l);
    }
}

