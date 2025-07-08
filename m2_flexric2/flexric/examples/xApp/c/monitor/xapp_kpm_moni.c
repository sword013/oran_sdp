/*
 * kpimon_xapp.c - FINAL VERSION (SERVER WITH NO SOFT CLIENT LIMIT)
 * This version will accept connections until the operating system's
 * file descriptor limit is reached, simulating a real DDoS scenario.
 */

#include "../../../../src/xApp/e42_xapp_api.h"
#include "../../../../src/util/alg_ds/alg/defer.h"
#include "../../../../src/util/time_now_us.h"
#include "../../../../src/util/alg_ds/ds/lock_guard/lock_guard.h"
#include "../../../../src/util/e.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

// MODIFICATION: Increase the client array size to be very large.
// The OS file descriptor limit (e.g., 1024) will be hit before this.
#define SERVER_PORT 9999
#define MAX_CLIENTS 10240

// Globals for TCP Server
static int listener_sock = -1;
static int client_sockets[MAX_CLIENTS];
static pthread_t acceptor_thread;
static volatile bool keep_running = true;
static pthread_mutex_t shared_data_mutex;

static uint64_t const period_ms = 1000;

// Acceptor thread function modified to remove the soft limit
void* acceptor_thread_func(void* arg) {
    printf("[SERVER] Acceptor thread started. Listening on port %d\n", SERVER_PORT);
    
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (keep_running) {
        // accept() will block until a connection arrives or an error occurs.
        int new_sock = accept(listener_sock, (struct sockaddr*)&client_addr, &client_addr_len);
        if (new_sock < 0) {
            if (keep_running) {
                // This error is expected under heavy load when file descriptor limit is reached.
                // The error message will likely be "Too many open files".
                perror("[SERVER] accept error (might be expected under DDoS)");
            }
            // If accept fails, we just loop back and try again.
            // This prevents a busy-loop on some error conditions.
            sleep(1); 
            continue;
        }

        bool slot_found = false;
        pthread_mutex_lock(&shared_data_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] == -1) {
                client_sockets[i] = new_sock;
                slot_found = true;
                break;
            }
        }
        pthread_mutex_unlock(&shared_data_mutex);
        
        // If the client_sockets array was full (highly unlikely),
        // we close the connection silently. The DDoS tool will see this 
        // as a dropped/failed connection.
        if (!slot_found) {
            close(new_sock);
        }
    }
    printf("[SERVER] Acceptor thread shutting down.\n");
    return NULL;
}

// Function to start the server
static void start_kpi_server() {
    struct sockaddr_in serv_addr;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = -1;
    }
    pthread_mutex_init(&shared_data_mutex, NULL);
    
    listener_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_sock < 0) {
        perror("[FATAL] socket");
        exit(EXIT_FAILURE);
    }
    
    int opt = 1;
    if (setsockopt(listener_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("[FATAL] setsockopt");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (bind(listener_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("[FATAL] bind");
        exit(EXIT_FAILURE);
    }

    // Increased backlog to handle more incoming connections before accept() is called
    if (listen(listener_sock, 256) < 0) {
        perror("[FATAL] listen");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&acceptor_thread, NULL, acceptor_thread_func, NULL) != 0) {
        perror("[FATAL] pthread_create");
        exit(EXIT_FAILURE);
    }
}

// Function to stop the server
static void stop_kpi_server() {
    keep_running = false;
    shutdown(listener_sock, SHUT_RDWR);
    close(listener_sock);
    
    printf("[SERVER] Waiting for acceptor thread to join...\n");
    pthread_join(acceptor_thread, NULL);

    pthread_mutex_lock(&shared_data_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_sockets[i] != -1) {
            close(client_sockets[i]);
        }
    }
    pthread_mutex_unlock(&shared_data_mutex);

    pthread_mutex_destroy(&shared_data_mutex);
    printf("[SERVER] KPI Server stopped.\n");
}

// Broadcast KPI data to all connected clients
static void broadcast_kpis_unsafe(const char* kpi_data) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_sockets[i] != -1) {
            // MSG_NOSIGNAL prevents the app from crashing if a client disconnects abruptly
            if (send(client_sockets[i], kpi_data, strlen(kpi_data), MSG_NOSIGNAL) < 0) {
                // Client disconnected, so we clean up
                printf("[SERVER] Client on socket %d disconnected. Removing.\n", client_sockets[i]);
                close(client_sockets[i]);
                client_sockets[i] = -1;
            }
        }
    }
}

// All logging and subscription helper functions are here for completeness
static void log_gnb_ue_id(ue_id_e2sm_t ue_id) { if (ue_id.gnb.gnb_cu_ue_f1ap_lst != NULL) { for (size_t i = 0; i < ue_id.gnb.gnb_cu_ue_f1ap_lst_len; i++) { printf("UE ID type = gNB-CU, gnb_cu_ue_f1ap = %u\n", ue_id.gnb.gnb_cu_ue_f1ap_lst[i]); } } else { printf("UE ID type = gNB, amf_ue_ngap_id = %lu\n", ue_id.gnb.amf_ue_ngap_id); } if (ue_id.gnb.ran_ue_id != NULL) { printf("ran_ue_id = %lx\n", *ue_id.gnb.ran_ue_id); } }
static void log_kpm_measurements(kpm_ind_msg_format_1_t const* msg_frm_1) { assert(msg_frm_1->meas_info_lst_len > 0); for (size_t j = 0; j < msg_frm_1->meas_data_lst_len; j++) { meas_data_lst_t const data_item = msg_frm_1->meas_data_lst[j]; for (size_t z = 0; z < data_item.meas_record_len; z++) { meas_type_t const meas_type = msg_frm_1->meas_info_lst[z].meas_type; meas_record_lst_t const record_item = data_item.meas_record_lst[z]; if(meas_type.type == NAME_MEAS_TYPE){ if (record_item.value == REAL_MEAS_VALUE){ if (cmp_str_ba("DRB.UEThpDl", meas_type.name) == 0) { printf("DRB.UEThpDl = %.2f [kbps]\n", record_item.real_val); } else if (cmp_str_ba("DRB.UEThpUl", meas_type.name) == 0) { printf("DRB.UEThpUl = %.2f [kbps]\n", record_item.real_val); } } } if (data_item.incomplete_flag && *data_item.incomplete_flag == TRUE_ENUM_VALUE) printf("Measurement Record not reliable"); } } }

static void sm_cb_kpm(sm_ag_if_rd_t const* rd) {
    assert(rd != NULL);
    kpm_ind_data_t const* ind = &rd->ind.kpm.ind;
    kpm_ric_ind_hdr_format_1_t const* hdr_frm_1 = &ind->hdr.kpm_ric_ind_hdr_format_1;
    kpm_ind_msg_format_3_t const* msg_frm_3 = &ind->msg.frm_3;
    int64_t const now = time_now_us();
    static int counter = 1;
    char send_buffer[8192] = {0};
    int offset = 0;

    pthread_mutex_lock(&shared_data_mutex);

    // --- Critical Section Start ---
    printf("\n%7d KPM ind_msg latency = %ld [μs]\n", counter, now - hdr_frm_1->collectStartTime);
    offset += snprintf(send_buffer + offset, sizeof(send_buffer) - offset, "\n%7d KPM ind_msg latency = %ld [μs]\n", counter, now - hdr_frm_1->collectStartTime);

    for (size_t i = 0; i < msg_frm_3->ue_meas_report_lst_len; i++) {
        // Log to local console
        log_gnb_ue_id(msg_frm_3->meas_report_per_ue[i].ue_meas_report_lst);
        log_kpm_measurements(&msg_frm_3->meas_report_per_ue[i].ind_msg_format_1);
        
        // You can add more snprintf calls here to format data for broadcast if needed
    }
    counter++;

    if (offset > 0) {
        broadcast_kpis_unsafe(send_buffer);
    }
    // --- Critical Section End ---
    pthread_mutex_unlock(&shared_data_mutex);
}

// Subscription helper functions
static test_info_lst_t filter_predicate(test_cond_type_e type, test_cond_e cond, int value) { test_info_lst_t dst = {0}; dst.test_cond_type = type; dst.S_NSSAI = TRUE_TEST_COND_TYPE; dst.test_cond = calloc(1, sizeof(test_cond_e)); assert(dst.test_cond != NULL); *dst.test_cond = cond; dst.test_cond_value = calloc(1, sizeof(test_cond_value_t)); assert(dst.test_cond_value != NULL); dst.test_cond_value->type = OCTET_STRING_TEST_COND_VALUE; dst.test_cond_value->octet_string_value = calloc(1, sizeof(byte_array_t)); assert(dst.test_cond_value->octet_string_value != NULL); dst.test_cond_value->octet_string_value->len = 1; dst.test_cond_value->octet_string_value->buf = calloc(1, sizeof(uint8_t)); assert(dst.test_cond_value->octet_string_value->buf != NULL); dst.test_cond_value->octet_string_value->buf[0] = value; return dst; }
static label_info_lst_t fill_kpm_label(void) { label_info_lst_t label_item = {0}; label_item.noLabel = ecalloc(1, sizeof(enum_value_e)); *label_item.noLabel = TRUE_ENUM_VALUE; return label_item; }
static kpm_act_def_format_1_t fill_act_def_frm_1(ric_report_style_item_t const* report_item) { assert(report_item != NULL); kpm_act_def_format_1_t ad_frm_1 = {0}; size_t const sz = report_item->meas_info_for_action_lst_len; ad_frm_1.meas_info_lst_len = sz; ad_frm_1.meas_info_lst = calloc(sz, sizeof(meas_info_format_1_lst_t)); assert(ad_frm_1.meas_info_lst != NULL); for (size_t i = 0; i < sz; i++) { meas_info_format_1_lst_t* meas_item = &ad_frm_1.meas_info_lst[i]; meas_item->meas_type.type = NAME_MEAS_TYPE; meas_item->meas_type.name = copy_byte_array(report_item->meas_info_for_action_lst[i].name); meas_item->label_info_lst_len = 1; meas_item->label_info_lst = ecalloc(1, sizeof(label_info_lst_t)); meas_item->label_info_lst[0] = fill_kpm_label(); } ad_frm_1.gran_period_ms = period_ms; ad_frm_1.cell_global_id = NULL; return ad_frm_1; }
static kpm_act_def_t fill_report_style_4(ric_report_style_item_t const* report_item) { assert(report_item != NULL); assert(report_item->act_def_format_type == FORMAT_4_ACTION_DEFINITION); kpm_act_def_t act_def = {.type = FORMAT_4_ACTION_DEFINITION}; act_def.frm_4.matching_cond_lst_len = 1; act_def.frm_4.matching_cond_lst = calloc(act_def.frm_4.matching_cond_lst_len, sizeof(matching_condition_format_4_lst_t)); assert(act_def.frm_4.matching_cond_lst != NULL); act_def.frm_4.matching_cond_lst[0].test_info_lst = filter_predicate(S_NSSAI_TEST_COND_TYPE, EQUAL_TEST_COND, 1); act_def.frm_4.action_def_format_1 = fill_act_def_frm_1(report_item); return act_def; }
typedef kpm_act_def_t (*fill_kpm_act_def)(ric_report_style_item_t const*);
static fill_kpm_act_def get_kpm_act_def[END_RIC_SERVICE_REPORT] = {NULL, NULL, NULL, fill_report_style_4, NULL,};
static kpm_sub_data_t gen_kpm_subs(kpm_ran_function_def_t const* ran_func) { assert(ran_func != NULL); kpm_sub_data_t kpm_sub = {0}; kpm_sub.ev_trg_def.type = FORMAT_1_RIC_EVENT_TRIGGER; kpm_sub.ev_trg_def.kpm_ric_event_trigger_format_1.report_period_ms = period_ms; kpm_sub.sz_ad = 1; kpm_sub.ad = calloc(kpm_sub.sz_ad, sizeof(kpm_act_def_t)); assert(kpm_sub.ad != NULL); ric_report_style_item_t* const report_item = &ran_func->ric_report_style_list[0]; *kpm_sub.ad = get_kpm_act_def[report_item->report_style_type](report_item); return kpm_sub; }
static bool eq_sm(sm_ran_function_t const* elem, int const id) { return elem->id == id; }
static size_t find_sm_idx(sm_ran_function_t* rf, size_t sz, bool (*f)(sm_ran_function_t const*, int const), int const id) { for (size_t i = 0; i < sz; i++) { if (f(&rf[i], id)) return i; } assert(0 && "SM ID could not be found"); return -1;}

int main(int argc, char* argv[]) {
    fr_args_t args = init_fr_args(argc, argv);
    start_kpi_server();
    init_xapp_api(&args);
    sleep(1);
    e2_node_arr_xapp_t nodes = e2_nodes_xapp_api();
    defer({ free_e2_node_arr_xapp(&nodes); });
    
    if (nodes.len == 0) {
        printf("No E2 nodes connected. Shutting down KPI server and exiting.\n");
        stop_kpi_server();
        return 1;
    }
    
    printf("Connected E2 nodes = %d\n", nodes.len);
    sm_ans_xapp_t* hndl = calloc(nodes.len, sizeof(sm_ans_xapp_t));
    assert(hndl != NULL);
    
    int const KPM_ran_function = 2;
    for (size_t i = 0; i < nodes.len; ++i) {
        e2_node_connected_xapp_t* n = &nodes.n[i];
        size_t const idx = find_sm_idx(n->rf, n->len_rf, eq_sm, KPM_ran_function);
        if (n->rf[idx].defn.kpm.ric_report_style_list != NULL) {
            kpm_sub_data_t kpm_sub = gen_kpm_subs(&n->rf[idx].defn.kpm);
            hndl[i] = report_sm_xapp_api(&n->id, KPM_ran_function, &kpm_sub, sm_cb_kpm);
            assert(hndl[i].success == true);
            free_kpm_sub_data(&kpm_sub);
        }
    }
    
    // Let the xApp run for a while
    printf("xApp is running. Press Ctrl+C to stop.\n");
    sleep(600); // Run for 10 minutes or until interrupted
    
    printf("Shutting down...\n");
    for (int i = 0; i < nodes.len; ++i) {
        if (hndl[i].success == true) {
            rm_report_sm_xapp_api(hndl[i].u.handle);
        }
    }
    free(hndl);
    
    while (try_stop_xapp_api() == false) {
        usleep(1000);
    }
    
    stop_kpi_server();
    printf("Test xApp run SUCCESSFULLY\n");
    return 0;
}


