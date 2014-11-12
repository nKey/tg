/*
    This file is part of telegram-cli.

    Telegram-cli is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Telegram-cli is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this telegram-cli.  If not, see <http://www.gnu.org/licenses/>.

    Copyright Vitaly Valtman 2013-2014
    Copyright Paul Eipper 2014
*/

#ifndef __LOOP_H__
#define __LOOP_H__

// fwd declaration
struct tgl_update_callback;
struct tgl_state;

struct tgl_config {
    // flags
    int sync_from_start;
    int wait_dialog_list;
    int reset_authorization;
    // callbacks
    const char *(*get_first_name) (void);
    const char *(*get_last_name) (void);
    const char *(*get_default_username) (void);
    const char *(*get_sms_code) (void);
    const char *(*get_auth_key_filename) (void);
    const char *(*get_state_filename) (void);
    const char *(*get_secret_chat_filename) (void);
    const char *(*get_download_directory) (void);
    const char *(*get_binlog_filename) (void);
    void (*set_default_username) (const char *username);
};

extern struct tgl_config config; // must be defined by caller

int loop(struct tgl_state *TLS, struct tgl_update_callback *upd_cb);
void wait_loop(struct tgl_state *TLS, int (*is_end)(struct tgl_state *TLS));
void write_secret_chat_file (struct tgl_state *TLS);

#endif /* defined(__LOOP_H__) */
