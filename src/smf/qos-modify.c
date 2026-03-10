/*
 * Copyright (C) 2024 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "qos-modify.h"
#include "gsm-handler.h"
#include "ngap-path.h"
#include "pfcp-path.h"
#include "sbi-path.h"
#include "sbi/openapi/external/cJSON.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __smf_log_domain

#define qos_flow_find_or_add(list, node, member)        \
    do {                                                \
        smf_bearer_t *iter = NULL;                      \
        bool found = false;                             \
                                                        \
        ogs_assert(node);                               \
                                                        \
        ogs_list_for_each_entry(list, iter, member) {   \
            if (iter->qfi == node->qfi) {               \
                found = true;                           \
                break;                                  \
            }                                           \
        }                                               \
        if (found == false) {                           \
            ogs_list_add(list, &node->member);          \
        }                                               \
    } while(0);

bool smf_qos_modify_handle_request(
    ogs_sbi_stream_t *stream, ogs_sbi_message_t *message, ogs_sbi_request_t *request)
{
    int rv;
    smf_ue_t *smf_ue = NULL;
    smf_sess_t *sess = NULL;
    smf_bearer_t *qos_flow = NULL;
    cJSON *json = NULL;
    cJSON *item = NULL;
    char *supi = NULL;
    int psi = 0;
    int qfi = 0;
    int five_qi = 0;
    uint64_t gbr_dl = 0;
    uint64_t gbr_ul = 0;
    uint64_t mbr_dl = 0;
    uint64_t mbr_ul = 0;
    bool has_gbr = false;
    bool has_mbr = false;

    ogs_assert(stream);
    ogs_assert(message);
    ogs_assert(request);

    /* Debug: log raw incoming body for troubleshooting */
    if (request->http.content && request->http.content_length > 0) {
        ogs_info("[QoS-MODIFY] Incoming request body: %.*s",
                 (int)request->http.content_length,
                 (const char *)request->http.content);
    } else {
        ogs_info("[QoS-MODIFY] Incoming request with empty body");
    }

    /* Parse JSON request body */
    if (!request->http.content || request->http.content_length == 0) {
        ogs_error("No request body");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST, message,
                "No request body", NULL, NULL));
        return false;
    }

    json = cJSON_Parse(request->http.content);
    if (!json) {
        ogs_error("Invalid JSON");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST, NULL,
                "Invalid JSON", NULL, NULL));
        return false;
    }

    /* Parse supi */
    item = cJSON_GetObjectItem(json, "supi");
    if (!item || !cJSON_IsString(item)) {
        ogs_error("[QoS-MODIFY] No supi or invalid type");
        cJSON_Delete(json);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST, NULL,
                "No supi or invalid type", NULL, NULL));
        return false;
    }
    supi = cJSON_GetStringValue(item);

    /* Parse psi */
    item = cJSON_GetObjectItem(json, "psi");
    if (!item || !cJSON_IsNumber(item)) {
        ogs_error("[QoS-MODIFY] No psi or invalid type");
        cJSON_Delete(json);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST, NULL,
                "No psi or invalid type", NULL, NULL));
        return false;
    }
    psi = item->valueint;

    /* Parse qfi */
    item = cJSON_GetObjectItem(json, "qfi");
    if (!item || !cJSON_IsNumber(item)) {
        ogs_error("[QoS-MODIFY] No qfi or invalid type");
        cJSON_Delete(json);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST, NULL,
                "No qfi or invalid type", NULL, NULL));
        return false;
    }
    qfi = item->valueint;

    /* Parse 5qi */
    item = cJSON_GetObjectItem(json, "5qi");
    if (!item || !cJSON_IsNumber(item)) {
        ogs_error("[QoS-MODIFY] No 5qi or invalid type");
        cJSON_Delete(json);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST, NULL,
                "No 5qi or invalid type", NULL, NULL));
        return false;
    }
    five_qi = item->valueint;

    /* Parse gbr_dl (optional) */
    item = cJSON_GetObjectItem(json, "gbr_dl");
    if (item && cJSON_IsNumber(item)) {
        gbr_dl = (uint64_t)item->valuedouble;
        has_gbr = true;
    }

    /* Parse gbr_ul (optional) */
    item = cJSON_GetObjectItem(json, "gbr_ul");
    if (item && cJSON_IsNumber(item)) {
        gbr_ul = (uint64_t)item->valuedouble;
        has_gbr = true;
    }

    /* Parse mbr_dl (optional) */
    item = cJSON_GetObjectItem(json, "mbr_dl");
    if (item && cJSON_IsNumber(item)) {
        mbr_dl = (uint64_t)item->valuedouble;
        has_mbr = true;
    }

    /* Parse mbr_ul (optional) */
    item = cJSON_GetObjectItem(json, "mbr_ul");
    if (item && cJSON_IsNumber(item)) {
        mbr_ul = (uint64_t)item->valuedouble;
        has_mbr = true;
    }

    cJSON_Delete(json);

    ogs_info("[QoS-MODIFY] Parsed JSON: supi=%s psi=%d qfi=%d 5qi=%d gbr_dl=%llu gbr_ul=%llu mbr_dl=%llu mbr_ul=%llu",
             supi, psi, qfi, five_qi,
             (unsigned long long)gbr_dl, (unsigned long long)gbr_ul,
             (unsigned long long)mbr_dl, (unsigned long long)mbr_ul);

    /* Find UE by SUPI */
    smf_ue = smf_ue_find_by_supi(supi);
    if (!smf_ue) {
        ogs_error("[QoS-MODIFY] UE not found [%s]", supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_FOUND, NULL,
                "UE not found", supi, NULL));
        return false;
    }

    /* Find session by PSI */
    sess = NULL;
    ogs_list_for_each(&smf_ue->sess_list, sess) {
        if (sess->psi == psi)
            break;
    }
    if (!sess || sess->psi != psi) {
        ogs_error("[QoS-MODIFY] Session not found [%s:%d]", supi, psi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_FOUND, NULL,
                "Session not found", supi, NULL));
        return false;
    }

    /* Find QoS Flow by QFI */
    qos_flow = smf_qos_flow_find_by_qfi(sess, qfi);
    if (!qos_flow) {
        ogs_error("[QoS-MODIFY] QoS Flow not found [%s:%d:%d]", supi, psi, qfi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_FOUND, NULL,
                "QoS Flow not found", supi, NULL));
        return false;
    }

    ogs_info("[QoS-MODIFY] Modifying QoS Flow [%s:%d:%d] 5QI=%d GBR_DL=%llu GBR_UL=%llu MBR_DL=%llu MBR_UL=%llu",
            supi, psi, qfi, five_qi,
            (unsigned long long)gbr_dl, (unsigned long long)gbr_ul,
            (unsigned long long)mbr_dl, (unsigned long long)mbr_ul);

    /* Update 5QI */
    ogs_info("[QoS-MODIFY] Before update: QFI=%d, 5QI=%d", qfi, qos_flow->qos.index);
    qos_flow->qos.index = five_qi;
    ogs_info("[QoS-MODIFY] After update: QFI=%d, 5QI=%d", qfi, qos_flow->qos.index);

    /* Update GBR if provided */
    if (has_gbr) {
        if (gbr_dl > 0)
            qos_flow->qos.gbr.downlink = gbr_dl;
        if (gbr_ul > 0)
            qos_flow->qos.gbr.uplink = gbr_ul;
        
        /* For GBR QoS Flow, if MBR is not provided, use GBR value as MBR */
        if (!has_mbr) {
            if (gbr_dl > 0 && qos_flow->qos.mbr.downlink == 0)
                qos_flow->qos.mbr.downlink = gbr_dl;
            if (gbr_ul > 0 && qos_flow->qos.mbr.uplink == 0)
                qos_flow->qos.mbr.uplink = gbr_ul;
        }
    }

    /* Update MBR if provided */
    if (has_mbr) {
        if (mbr_dl > 0)
            qos_flow->qos.mbr.downlink = mbr_dl;
        if (mbr_ul > 0)
            qos_flow->qos.mbr.uplink = mbr_ul;
    }

    /* Update QoS parameters */
    smf_bearer_qos_update(qos_flow);

    /* Add to modify list */
    ogs_list_init(&sess->qos_flow_to_modify_list);
    qos_flow_find_or_add(&sess->qos_flow_to_modify_list,
            qos_flow, to_modify_node);

    /*
     * Send PFCP modification request
     *
     * Flags:
     *  - OGS_PFCP_MODIFY_SESSION          : this is a per-session QoS update
     *  - OGS_PFCP_MODIFY_NETWORK_REQUESTED: network-triggered (SMF-initiated)
     *  - OGS_PFCP_MODIFY_QOS_MODIFY       : modify existing QoS flow
     *
     * Using only OGS_PFCP_MODIFY_QOS_MODIFY would cause the N4 handler
     * to treat the flag combination as unknown and abort. Marking the
     * update as NETWORK_REQUESTED + SESSION aligns with existing flows
     * and enables the correct NAS/NGAP/N4 handling path.
     */
    rv = smf_5gc_pfcp_send_one_qos_flow_modification_request(
            qos_flow, NULL,
            OGS_PFCP_MODIFY_SESSION |
                OGS_PFCP_MODIFY_NETWORK_REQUESTED |
                OGS_PFCP_MODIFY_QOS_MODIFY,
            0);
    if (rv != OGS_OK) {
        ogs_error("PFCP modification request failed [%s:%d:%d]",
                supi, psi, qfi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL,
                "PFCP modification request failed", supi, NULL));
        return false;
    }

    /* Send NGAP modification request */
    smf_n1_n2_message_transfer_param_t param;
    memset(&param, 0, sizeof(param));
    param.state = SMF_NETWORK_REQUESTED_QOS_FLOW_MODIFICATION;
    param.n1smbuf = gsm_build_pdu_session_modification_command(sess, 0, 0);
    if (!param.n1smbuf) {
        ogs_error("Failed to build PDU Session Modification Command");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL,
                "Failed to build PDU Session Modification Command", supi, NULL));
        return false;
    }

    param.n2smbuf = ngap_build_pdu_session_resource_modify_request_transfer(
            sess, has_gbr && (gbr_dl > 0 || gbr_ul > 0));
    if (!param.n2smbuf) {
        ogs_error("Failed to build PDU Session Resource Modify Request");
        ogs_pkbuf_free(param.n1smbuf);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL,
                "Failed to build PDU Session Resource Modify Request", supi, NULL));
        return false;
    }

    if (sess->establishment_accept_sent == true) {
        smf_namf_comm_send_n1_n2_message_transfer(sess, NULL, &param);
    } else {
        ogs_pkbuf_free(param.n1smbuf);
        ogs_pkbuf_free(param.n2smbuf);
    }

    /* Send success response */
    ogs_assert(true == ogs_sbi_send_http_status_no_content(stream));

    return true;
}



