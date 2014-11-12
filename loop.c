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

#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <event2/event.h>

#include "loop.h"
#include "binlog.h"
#include "net.h"
#include "tgl-timers.h"
#include "structures.h"

#define DC_SERIALIZED_MAGIC 0x868aa81d
#define STATE_FILE_MAGIC 0x28949a93
#define SECRET_CHAT_FILE_MAGIC 0x37a1988a

void _dummy_logprintf(const char *format, ...) {};
void (*logprintf)(const char *format, ...) = _dummy_logprintf;


// config functions

const char *get_downloads_directory (void) {
    return config.get_download_directory ();
}

const char *get_binlog_file_name (void) {
    return config.get_binlog_filename ();
}


// loader functions

void read_state_file (struct tgl_state *TLS) {
    int state_file_fd = open (config.get_state_filename (), O_CREAT | O_RDWR, 0600);
    if (state_file_fd < 0) {
        return;
    }
    int version, magic;
    if (read (state_file_fd, &magic, 4) < 4) { close (state_file_fd); return; }
    if (magic != (int)STATE_FILE_MAGIC) { close (state_file_fd); return; }
    if (read (state_file_fd, &version, 4) < 4) { close (state_file_fd); return; }
    assert (version >= 0);
    int x[4];
    if (read (state_file_fd, x, 16) < 16) {
        close (state_file_fd);
        return;
    }
    int pts = x[0];
    int qts = x[1];
    int seq = x[2];
    int date = x[3];
    close (state_file_fd);
    bl_do_set_seq (TLS, seq);
    bl_do_set_pts (TLS, pts);
    bl_do_set_qts (TLS, qts);
    bl_do_set_date (TLS, date);
}

void write_state_file (struct tgl_state *TLS) {
    static int wseq;
    static int wpts;
    static int wqts;
    static int wdate;
    if (wseq >= TLS->seq && wpts >= TLS->pts && wqts >= TLS->qts && wdate >= TLS->date) { return; }
    wseq = TLS->seq; wpts = TLS->pts; wqts = TLS->qts; wdate = TLS->date;
    int state_file_fd = open (config.get_state_filename (), O_CREAT | O_RDWR, 0600);
    if (state_file_fd < 0) {
        logprintf ("Can not write state file '%s': %m\n", config.get_state_filename ());
        exit (1);
    }
    int x[6];
    x[0] = STATE_FILE_MAGIC;
    x[1] = 0;
    x[2] = wpts;
    x[3] = wqts;
    x[4] = wseq;
    x[5] = wdate;
    assert (write (state_file_fd, x, 24) == 24);
    close (state_file_fd);
}

void write_dc (struct tgl_dc *DC, void *extra) {
    int auth_file_fd = *(int *)extra;
    if (!DC) {
        int x = 0;
        assert (write (auth_file_fd, &x, 4) == 4);
        return;
    } else {
        int x = 1;
        assert (write (auth_file_fd, &x, 4) == 4);
    }
    
    assert (DC->has_auth);
    
    assert (write (auth_file_fd, &DC->port, 4) == 4);
    int l = (int)(strlen (DC->ip));
    assert (write (auth_file_fd, &l, 4) == 4);
    assert (write (auth_file_fd, DC->ip, l) == l);
    assert (write (auth_file_fd, &DC->auth_key_id, 8) == 8);
    assert (write (auth_file_fd, DC->auth_key, 256) == 256);
}

void write_auth_file (struct tgl_state *TLS) {
    int auth_file_fd = open (config.get_auth_key_filename (), O_CREAT | O_RDWR, 0600);
    assert (auth_file_fd >= 0);
    int x = DC_SERIALIZED_MAGIC;
    assert (write (auth_file_fd, &x, 4) == 4);
    assert (write (auth_file_fd, &TLS->max_dc_num, 4) == 4);
    assert (write (auth_file_fd, &TLS->dc_working_num, 4) == 4);
    
    tgl_dc_iterator_ex (TLS, write_dc, &auth_file_fd);
    
    assert (write (auth_file_fd, &TLS->our_id, 4) == 4);
    close (auth_file_fd);
}

void write_secret_chat (tgl_peer_t *_P, void *extra) {
    struct tgl_secret_chat *P = (void *)_P;
    if (tgl_get_peer_type (P->id) != TGL_PEER_ENCR_CHAT) { return; }
    if (P->state != sc_ok) { return; }
    int *a = extra;
    int fd = a[0];
    a[1] ++;
    
    int id = tgl_get_peer_id (P->id);
    assert (write (fd, &id, 4) == 4);
    //assert (write (fd, &P->flags, 4) == 4);
    int l = (int)(strlen (P->print_name));
    assert (write (fd, &l, 4) == 4);
    assert (write (fd, P->print_name, l) == l);
    assert (write (fd, &P->user_id, 4) == 4);
    assert (write (fd, &P->admin_id, 4) == 4);
    assert (write (fd, &P->date, 4) == 4);
    assert (write (fd, &P->ttl, 4) == 4);
    assert (write (fd, &P->layer, 4) == 4);
    assert (write (fd, &P->access_hash, 8) == 8);
    assert (write (fd, &P->state, 4) == 4);
    assert (write (fd, &P->key_fingerprint, 8) == 8);
    assert (write (fd, &P->key, 256) == 256);
    assert (write (fd, &P->in_seq_no, 4) == 4);
    assert (write (fd, &P->last_in_seq_no, 4) == 4);
    assert (write (fd, &P->out_seq_no, 4) == 4);
}

void write_secret_chat_file (struct tgl_state *TLS) {
    int secret_chat_fd = open (config.get_secret_chat_filename (), O_CREAT | O_RDWR, 0600);
    assert (secret_chat_fd >= 0);
    int x = SECRET_CHAT_FILE_MAGIC;
    assert (write (secret_chat_fd, &x, 4) == 4);
    x = 1;
    assert (write (secret_chat_fd, &x, 4) == 4); // version
    assert (write (secret_chat_fd, &x, 4) == 4); // num
    
    int y[2];
    y[0] = secret_chat_fd;
    y[1] = 0;
    
    tgl_peer_iterator_ex (TLS, write_secret_chat, y);
    
    lseek (secret_chat_fd, 8, SEEK_SET);
    assert (write (secret_chat_fd, &y[1], 4) == 4);
    close (secret_chat_fd);
}

void read_dc (struct tgl_state *TLS, int auth_file_fd, int id, unsigned ver) {
    int port = 0;
    assert (read (auth_file_fd, &port, 4) == 4);
    int l = 0;
    assert (read (auth_file_fd, &l, 4) == 4);
    assert (l >= 0 && l < 100);
    char ip[100];
    assert (read (auth_file_fd, ip, l) == l);
    ip[l] = 0;
    
    long long auth_key_id;
    static unsigned char auth_key[256];
    assert (read (auth_file_fd, &auth_key_id, 8) == 8);
    assert (read (auth_file_fd, auth_key, 256) == 256);
    
    //bl_do_add_dc (id, ip, l, port, auth_key_id, auth_key);
    bl_do_dc_option (TLS, id, 2, "DC", l, ip, port);
    bl_do_set_auth_key_id (TLS, id, auth_key);
    bl_do_dc_signed (TLS, id);
}

void empty_auth_file (struct tgl_state *TLS) {
    if (TLS->test_mode) {
        bl_do_dc_option (TLS, 1, 0, "", strlen (TG_SERVER_TEST_1), TG_SERVER_TEST_1, 443);
        bl_do_dc_option (TLS, 2, 0, "", strlen (TG_SERVER_TEST_2), TG_SERVER_TEST_2, 443);
        bl_do_dc_option (TLS, 3, 0, "", strlen (TG_SERVER_TEST_3), TG_SERVER_TEST_3, 443);
        bl_do_set_working_dc (TLS, 2);
    } else {
        bl_do_dc_option (TLS, 1, 0, "", strlen (TG_SERVER_1), TG_SERVER_1, 443);
        bl_do_dc_option (TLS, 2, 0, "", strlen (TG_SERVER_2), TG_SERVER_2, 443);
        bl_do_dc_option (TLS, 3, 0, "", strlen (TG_SERVER_3), TG_SERVER_3, 443);
        bl_do_dc_option (TLS, 4, 0, "", strlen (TG_SERVER_4), TG_SERVER_4, 443);
        bl_do_dc_option (TLS, 5, 0, "", strlen (TG_SERVER_5), TG_SERVER_5, 443);
        bl_do_set_working_dc (TLS, 4);
    }
}

void read_auth_file (struct tgl_state *TLS) {
    int auth_file_fd = open (config.get_auth_key_filename (), O_CREAT | O_RDWR, 0600);
    if (auth_file_fd < 0) {
        empty_auth_file (TLS);
        return;
    }
    assert (auth_file_fd >= 0);
    unsigned x;
    unsigned m;
    if (read (auth_file_fd, &m, 4) < 4 || (m != DC_SERIALIZED_MAGIC)) {
        close (auth_file_fd);
        empty_auth_file (TLS);
        return;
    }
    assert (read (auth_file_fd, &x, 4) == 4);
    assert (x > 0);
    int dc_working_num;
    assert (read (auth_file_fd, &dc_working_num, 4) == 4);
    
    int i;
    for (i = 0; i <= (int)x; i++) {
        int y;
        assert (read (auth_file_fd, &y, 4) == 4);
        if (y) {
            read_dc (TLS, auth_file_fd, i, m);
        }
    }
    bl_do_set_working_dc (TLS, dc_working_num);
    int our_id;
    int l = (int)(read (auth_file_fd, &our_id, 4));
    if (l < 4) {
        assert (!l);
    }
    if (our_id) {
        bl_do_set_our_id (TLS, our_id);
    }
    close (auth_file_fd);
}

void read_secret_chat (struct tgl_state *TLS, int fd, int v) {
    int id, l, user_id, admin_id, date, ttl, layer, state;
    long long access_hash, key_fingerprint;
    static char s[1000];
    static unsigned char key[256];
    assert (read (fd, &id, 4) == 4);
    //assert (read (fd, &flags, 4) == 4);
    assert (read (fd, &l, 4) == 4);
    assert (l > 0 && l < 1000);
    assert (read (fd, s, l) == l);
    assert (read (fd, &user_id, 4) == 4);
    assert (read (fd, &admin_id, 4) == 4);
    assert (read (fd, &date, 4) == 4);
    assert (read (fd, &ttl, 4) == 4);
    assert (read (fd, &layer, 4) == 4);
    assert (read (fd, &access_hash, 8) == 8);
    assert (read (fd, &state, 4) == 4);
    assert (read (fd, &key_fingerprint, 8) == 8);
    assert (read (fd, &key, 256) == 256);
    int in_seq_no = 0, out_seq_no = 0, last_in_seq_no = 0;
    if (v >= 1) {
        assert (read (fd, &in_seq_no, 4) == 4);
        assert (read (fd, &last_in_seq_no, 4) == 4);
        assert (read (fd, &out_seq_no, 4) == 4);
    }
    
    bl_do_encr_chat_create (TLS, id, user_id, admin_id, s, l);
    struct tgl_secret_chat  *P = (void *)tgl_peer_get (TLS, TGL_MK_ENCR_CHAT (id));
    assert (P && (P->flags & FLAG_CREATED));
    bl_do_encr_chat_set_date (TLS, P, date);
    bl_do_encr_chat_set_ttl (TLS, P, ttl);
    bl_do_encr_chat_set_layer (TLS, P, layer);
    bl_do_encr_chat_set_access_hash (TLS, P, access_hash);
    bl_do_encr_chat_set_state (TLS, P, state);
    bl_do_encr_chat_set_key (TLS, P, key, key_fingerprint);
    if (v >= 1) {
        bl_do_encr_chat_set_seq (TLS, P, in_seq_no, last_in_seq_no, out_seq_no);
    }
}

void read_secret_chat_file (struct tgl_state *TLS) {
    int secret_chat_fd = open (config.get_secret_chat_filename (), O_RDWR, 0600);
    if (secret_chat_fd < 0) { return; }
    //assert (secret_chat_fd >= 0);
    int x;
    if (read (secret_chat_fd, &x, 4) < 4) { close (secret_chat_fd); return; }
    if (x != SECRET_CHAT_FILE_MAGIC) { close (secret_chat_fd); return; }
    int v = 0;
    assert (read (secret_chat_fd, &v, 4) == 4);
    assert (v == 0 || v == 1); // version
    assert (read (secret_chat_fd, &x, 4) == 4);
    assert (x >= 0);
    while (x --> 0) {
        read_secret_chat (TLS, secret_chat_fd, v);
    }
    close (secret_chat_fd);
}


// loop callbacks

struct tgl_dc *cur_a_dc;
int is_authorized (struct tgl_state *TLS) {
    return tgl_authorized_dc (TLS, cur_a_dc);
}

int all_authorized (struct tgl_state *TLS) {
    int i;
    for (i = 0; i <= TLS->max_dc_num; i++) if (TLS->DC_list[i]) {
        if (!tgl_authorized_dc (TLS, TLS->DC_list[i])) {
            return 0;
        }
    }
    return 1;
}

int should_register;
char *hash;
void sign_in_callback (struct tgl_state *TLS, void *extra, int success, int registered, const char *mhash) {
    if (!success) {
        logprintf("Can not send code");
        exit (1);
    }
    should_register = !registered;
    hash = strdup (mhash);
}

int signed_in_result;
void sign_in_result (struct tgl_state *TLS, void *extra, int success, struct tgl_user *U) {
    signed_in_result = success ? 1 : 2;
}

int signed_in (struct tgl_state *TLS) {
    return signed_in_result;
}

int sent_code (struct tgl_state *TLS) {
    return hash != 0;
}

int dc_signed_in (struct tgl_state *TLS) {
    return tgl_signed_dc (TLS, cur_a_dc);
}

void export_auth_callback (struct tgl_state *TLS, void *DC, int success) {
    if (!success) {
        logprintf ("Can not export auth\n");
        exit (1);
    }
}

int d_got_ok;
void get_difference_callback (struct tgl_state *TLS, void *extra, int success) {
    assert (success);
    d_got_ok = 1;
}

int dgot (struct tgl_state *TLS) {
    return d_got_ok;
}

void dlist_cb (struct tgl_state *TLS, void *callback_extra, int success, int size, tgl_peer_id_t peers[], int last_msg_id[], int unread_count[])  {
    d_got_ok = 1;
}


// main loops

void net_loop (struct tgl_state *TLS, int flags, int (*is_end)(struct tgl_state *TLS)) {
    int last_get_state = (int)(time (0));
    while (!is_end || !is_end (TLS)) {
        event_base_loop (TLS->ev_base, EVLOOP_ONCE);
        if (time (0) - last_get_state > 3600) {
            tgl_do_lookup_state (TLS);
            last_get_state = (int)(time (0));
        }
    }
}

void wait_loop(struct tgl_state *TLS, int (*is_end)(struct tgl_state *TLS)) {
    net_loop (TLS, 0, is_end);
}

int main_loop (struct tgl_state *TLS) {
    net_loop (TLS, 1, 0);
    return 0;
}

int loop(struct tgl_state *TLS, struct tgl_update_callback *upd_cb) {
    logprintf = upd_cb->logprintf;
    tgl_set_binlog_mode (TLS, 0);
    tgl_set_download_directory (TLS, config.get_download_directory ());
    tgl_set_callback (TLS, upd_cb);
    //TLS->temp_key_expire_time = 60;
    struct event_base *ev = event_base_new ();
    tgl_set_ev_base (TLS, ev);
    tgl_set_net_methods (TLS, &tgl_conn_methods);
    tgl_set_timer_methods (TLS, &tgl_libevent_timers);
    tgl_init (TLS);
    read_auth_file (TLS);
    read_state_file (TLS);
    read_secret_chat_file (TLS);
    if (config.reset_authorization) {
        tgl_peer_t *P = tgl_peer_get (TLS, TGL_MK_USER (TLS->our_id));
        if (P && P->user.phone && config.reset_authorization == 1) {
            logprintf("Try to login as %s", P->user.phone);
            config.set_default_username(P->user.phone);
        }
        bl_do_reset_authorization (TLS);
    }
    net_loop (TLS, 0, all_authorized);
    if (!tgl_signed_dc(TLS, TLS->DC_working)) {
        logprintf("Need to login first");
        tgl_do_send_code(TLS, config.get_default_username (), sign_in_callback, 0);
        net_loop(TLS, 0, sent_code);
        logprintf ("%s\n", should_register ? "phone not registered" : "phone registered");
        if (!should_register) {
            logprintf("Enter SMS code");
            const char *username = config.get_default_username ();
            while (1) {
                const char *sms_code = config.get_sms_code ();
                tgl_do_send_code_result (TLS, username, hash, sms_code, sign_in_result, 0);
                net_loop (TLS, 0, signed_in);
                if (signed_in_result == 1) {
                    break;
                }
                logprintf("Invalid code");
                signed_in_result = 0;
            }
        } else {
            logprintf("User is not registered");
            const char *username = config.get_default_username ();
            const char *first_name = config.get_first_name ();
            const char *last_name = config.get_last_name ();
            while (1) {
                const char *sms_code = config.get_sms_code ();
                tgl_do_send_code_result_auth (TLS, username, hash, sms_code, first_name, last_name, sign_in_result, 0);
                net_loop (TLS, 0, signed_in);
                if (signed_in_result == 1) {
                    break;
                }
                logprintf("Invalid code");
                signed_in_result = 0;
            }
        }
    }
    for (int i = 0; i <= TLS->max_dc_num; i++) if (TLS->DC_list[i] && !tgl_signed_dc (TLS, TLS->DC_list[i])) {
        tgl_do_export_auth (TLS, i, export_auth_callback, (void*)(long)TLS->DC_list[i]);
        cur_a_dc = TLS->DC_list[i];
        net_loop (TLS, 0, dc_signed_in);
        assert (tgl_signed_dc (TLS, TLS->DC_list[i]));
    }
    write_auth_file (TLS);
    tglm_send_all_unsent (TLS);
    tgl_do_get_difference (TLS, config.sync_from_start, get_difference_callback, 0);
    net_loop (TLS, 0, dgot);
    assert (!(TLS->locks & TGL_LOCK_DIFF));
    TLS->started = 1;
    if (config.wait_dialog_list) {
        d_got_ok = 0;
        tgl_do_get_dialog_list (TLS, dlist_cb, 0);
        net_loop (TLS, 0, dgot);
    }
    return main_loop(TLS);
}
