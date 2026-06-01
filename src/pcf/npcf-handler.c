/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#include <sys/time.h>

#include "sbi-path.h"

#include "npcf-handler.h"

/*
 * Lab extension for dynamic QoS on an existing QoS flow (AF/iperf via
 * Npcf_PolicyAuthorization only — no separate PCF API).
 *
 * Set ascReqData.afAppId to:
 *   5GC-QOS:<qfi>:<5qi>[:<gbr_dl>][:<gbr_ul>][:<mbr_dl>][:<mbr_ul>]
 * Example: 5GC-QOS:1:66:20000000:20000000
 *
 * PCF builds SmPolicyDecision (qosDecs "qfi-N" only) and uses the existing
 * SmPolicyControl update-notify path toward SMF.
 */
#define PCF_QOS_TARGET_AF_PREFIX        "5GC-QOS:"
#define PCF_QOS_TARGET_QOS_ID_PREFIX    "qfi-"

/* TS 23.501 — only GBR / Delay-critical GBR 5QIs carry bitrates in PolicyAuth. */
static bool pcf_policyauth_five_qi_needs_bitrate(int five_qi)
{
    switch (five_qi) {
    case 1: case 2: case 3: case 4:
    case 65: case 66: case 67:
    case 75:
    case 82: case 83: case 84: case 85:
        return true;
    default:
        return false;
    }
}

/*
 * Log when a Policy Authorization API request is first handled (POST/PATCH).
 * Correlates with AF curl in iperf3_dynamic_5qi_pcf.sh (wall clock, local TZ).
 */
static void pcf_policyauth_log_api_ingress(
        const char *method, pcf_sess_t *sess, pcf_ue_sm_t *pcf_ue_sm,
        pcf_app_t *app_session, ogs_sbi_message_t *recvmsg, bool is_patch)
{
    struct timeval wall;
    struct tm tm_local;
    const char *af_app_id = NULL;
    time_t sec;

    ogs_assert(method);
    ogs_assert(sess);
    ogs_assert(recvmsg);

    if (is_patch) {
        if (recvmsg->AppSessionContextUpdateDataPatch &&
                recvmsg->AppSessionContextUpdateDataPatch->asc_req_data)
            af_app_id =
                recvmsg->AppSessionContextUpdateDataPatch->asc_req_data->af_app_id;
    } else if (recvmsg->AppSessionContext &&
            recvmsg->AppSessionContext->asc_req_data) {
        af_app_id = recvmsg->AppSessionContext->asc_req_data->af_app_id;
    }

    gettimeofday(&wall, NULL);
    sec = wall.tv_sec;
    localtime_r(&sec, &tm_local);

    if (pcf_ue_sm && app_session && app_session->app_session_id) {
        ogs_info("[PCF-API-INGRESS] %s wall=%02d:%02d:%02d.%06ld "
                "afAppId=%s supi=%s psi=%d appSessionId=%s",
                method,
                tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec,
                (long)wall.tv_usec,
                af_app_id ? af_app_id : "-",
                pcf_ue_sm->supi, sess->psi, app_session->app_session_id);
    } else if (pcf_ue_sm) {
        ogs_info("[PCF-API-INGRESS] %s wall=%02d:%02d:%02d.%06ld "
                "afAppId=%s supi=%s psi=%d",
                method,
                tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec,
                (long)wall.tv_usec,
                af_app_id ? af_app_id : "-",
                pcf_ue_sm->supi, sess->psi);
    } else {
        ogs_info("[PCF-API-INGRESS] %s wall=%02d:%02d:%02d.%06ld afAppId=%s",
                method,
                tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec,
                (long)wall.tv_usec,
                af_app_id ? af_app_id : "-");
    }
}

static bool pcf_policyauth_parse_qos_target_af_app_id(
        const char *af_app_id, uint8_t *qfi, int *five_qi,
        uint64_t *gbr_dl, uint64_t *gbr_ul,
        uint64_t *mbr_dl, uint64_t *mbr_ul,
        bool *has_gbr, bool *has_mbr)
{
    unsigned int qfi_u = 0;
    int n = 0;

    ogs_assert(af_app_id);
    ogs_assert(qfi);
    ogs_assert(five_qi);
    ogs_assert(gbr_dl);
    ogs_assert(gbr_ul);
    ogs_assert(mbr_dl);
    ogs_assert(mbr_ul);
    ogs_assert(has_gbr);
    ogs_assert(has_mbr);

    *has_gbr = false;
    *has_mbr = false;
    *gbr_dl = *gbr_ul = *mbr_dl = *mbr_ul = 0;

    if (strncmp(af_app_id, PCF_QOS_TARGET_AF_PREFIX,
                strlen(PCF_QOS_TARGET_AF_PREFIX)) != 0)
        return false;

    n = sscanf(af_app_id + strlen(PCF_QOS_TARGET_AF_PREFIX),
            "%u:%d", &qfi_u, five_qi);
    if (n < 2 || qfi_u == 0)
        return false;

    *qfi = (uint8_t)qfi_u;

    n = sscanf(af_app_id + strlen(PCF_QOS_TARGET_AF_PREFIX),
            "%*u:%*d:%llu:%llu:%llu:%llu",
            (unsigned long long *)gbr_dl,
            (unsigned long long *)gbr_ul,
            (unsigned long long *)mbr_dl,
            (unsigned long long *)mbr_ul);
    if (n >= 1) {
        *has_gbr = true;
        if (n >= 3)
            *has_mbr = true;
    }

    if (!pcf_policyauth_five_qi_needs_bitrate(*five_qi)) {
        *has_gbr = false;
        *has_mbr = false;
        *gbr_dl = *gbr_ul = *mbr_dl = *mbr_ul = 0;
    }

    return true;
}

static OpenAPI_qos_data_t *pcf_policyauth_build_qos_target_data(
        uint8_t qfi, int five_qi,
        uint64_t gbr_dl, uint64_t gbr_ul, uint64_t mbr_dl, uint64_t mbr_ul,
        bool has_gbr, bool has_mbr, ogs_qos_t *session_qos)
{
    OpenAPI_qos_data_t *QosData = NULL;
    char qos_id[16];

    ogs_assert(session_qos);

    QosData = ogs_calloc(1, sizeof(*QosData));
    ogs_assert(QosData);

    ogs_snprintf(qos_id, sizeof(qos_id), "%s%d",
            PCF_QOS_TARGET_QOS_ID_PREFIX, qfi);
    QosData->qos_id = ogs_strdup(qos_id);
    ogs_assert(QosData->qos_id);

    QosData->is__5qi = true;
    QosData->_5qi = five_qi;
    QosData->is_priority_level = true;
    QosData->priority_level = session_qos->arp.priority_level;

    QosData->arp = ogs_calloc(1, sizeof(OpenAPI_arp_t));
    ogs_assert(QosData->arp);

    if (session_qos->arp.pre_emption_capability == OGS_5GC_PRE_EMPTION_ENABLED)
        QosData->arp->preempt_cap = OpenAPI_preemption_capability_MAY_PREEMPT;
    else
        QosData->arp->preempt_cap =
            OpenAPI_preemption_capability_NOT_PREEMPT;

    if (session_qos->arp.pre_emption_vulnerability ==
            OGS_5GC_PRE_EMPTION_ENABLED)
        QosData->arp->preempt_vuln =
            OpenAPI_preemption_vulnerability_PREEMPTABLE;
    else
        QosData->arp->preempt_vuln =
            OpenAPI_preemption_vulnerability_NOT_PREEMPTABLE;

    QosData->arp->priority_level = session_qos->arp.priority_level;

    if (!pcf_policyauth_five_qi_needs_bitrate(five_qi)) {
        has_gbr = false;
        has_mbr = false;
        gbr_dl = gbr_ul = mbr_dl = mbr_ul = 0;
    }

    if (has_mbr) {
        if (mbr_dl > 0)
            QosData->maxbr_dl = ogs_sbi_bitrate_to_string(
                    mbr_dl, OGS_SBI_BITRATE_BPS);
        if (mbr_ul > 0)
            QosData->maxbr_ul = ogs_sbi_bitrate_to_string(
                    mbr_ul, OGS_SBI_BITRATE_BPS);
    }

    if (has_gbr) {
        if (gbr_dl > 0)
            QosData->gbr_dl = ogs_sbi_bitrate_to_string(
                    gbr_dl, OGS_SBI_BITRATE_BPS);
        if (gbr_ul > 0)
            QosData->gbr_ul = ogs_sbi_bitrate_to_string(
                    gbr_ul, OGS_SBI_BITRATE_BPS);
    }

    return QosData;
}

static void pcf_policyauth_log_qos_target(
        const char *event, pcf_ue_sm_t *pcf_ue_sm, pcf_sess_t *sess,
        const char *af_app_id, uint8_t qfi, int five_qi,
        uint64_t gbr_dl, uint64_t gbr_ul, uint64_t mbr_dl, uint64_t mbr_ul,
        bool has_gbr, bool has_mbr)
{
    ogs_assert(event);
    ogs_assert(pcf_ue_sm);
    ogs_assert(sess);

    if (af_app_id) {
        ogs_info("[PolicyAuth-QoS] %s [%s:%d] afAppId=%s",
                event, pcf_ue_sm->supi, sess->psi, af_app_id);
    }

    if (has_gbr || has_mbr) {
        ogs_info("[PolicyAuth-QoS] %s [%s:%d] qfi=%d 5qi=%d"
                " gbr_dl=%llu gbr_ul=%llu mbr_dl=%llu mbr_ul=%llu",
                event, pcf_ue_sm->supi, sess->psi, qfi, five_qi,
                (unsigned long long)gbr_dl, (unsigned long long)gbr_ul,
                (unsigned long long)mbr_dl, (unsigned long long)mbr_ul);
    } else {
        ogs_info("[PolicyAuth-QoS] %s [%s:%d] qfi=%d 5qi=%d",
                event, pcf_ue_sm->supi, sess->psi, qfi, five_qi);
    }
}

static void pcf_policyauth_free_qos_target_decision(
        OpenAPI_list_t *QosDecisionList)
{
    OpenAPI_lnode_t *node = NULL;
    OpenAPI_map_t *QosDecisionMap = NULL;
    OpenAPI_qos_data_t *QosData = NULL;

    if (!QosDecisionList)
        return;

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);
}

static bool pcf_policyauth_send_qos_target_notify(
        pcf_sess_t *sess, pcf_ue_sm_t *pcf_ue_sm,
        uint8_t qfi, int five_qi,
        uint64_t gbr_dl, uint64_t gbr_ul, uint64_t mbr_dl, uint64_t mbr_ul,
        bool has_gbr, bool has_mbr)
{
    int rv;
    ogs_session_data_t session_data;
    OpenAPI_sm_policy_decision_t SmPolicyDecision;
    OpenAPI_list_t *QosDecisionList = NULL;
    OpenAPI_map_t *QosDecisionMap = NULL;
    OpenAPI_qos_data_t *QosData = NULL;

    ogs_assert(sess);
    ogs_assert(pcf_ue_sm);

    if (!sess->nsmf.client) {
        ogs_error("[PolicyAuth-QoS] No SMF association [%s:%d]",
                pcf_ue_sm->supi, sess->psi);
        return false;
    }

    memset(&session_data, 0, sizeof(session_data));
    rv = pcf_get_session_data(
            pcf_ue_sm->supi,
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, sess->dnn, &session_data, 0);
    if (rv != OGS_OK) {
        ogs_error("[PolicyAuth-QoS] Cannot load session data [%s:%d]",
                pcf_ue_sm->supi, sess->psi);
        return false;
    }

    pcf_policyauth_log_qos_target("PCF->SMF notify", pcf_ue_sm, sess,
            NULL, qfi, five_qi, gbr_dl, gbr_ul, mbr_dl, mbr_ul,
            has_gbr, has_mbr);

    memset(&SmPolicyDecision, 0, sizeof(SmPolicyDecision));

    QosDecisionList = OpenAPI_list_create();
    ogs_assert(QosDecisionList);

    QosData = pcf_policyauth_build_qos_target_data(
            qfi, five_qi, gbr_dl, gbr_ul, mbr_dl, mbr_ul,
            has_gbr, has_mbr, &session_data.session.qos);
    ogs_assert(QosData);

    QosDecisionMap = OpenAPI_map_create(QosData->qos_id, QosData);
    ogs_assert(QosDecisionMap);
    OpenAPI_list_add(QosDecisionList, QosDecisionMap);

    SmPolicyDecision.qos_decs = QosDecisionList;

    if (!pcf_sbi_send_smpolicycontrol_update_notify(sess, &SmPolicyDecision)) {
        ogs_error("[PolicyAuth-QoS] SmPolicyControl update notify failed");
        pcf_policyauth_free_qos_target_decision(QosDecisionList);
        OGS_SESSION_DATA_FREE(&session_data);
        return false;
    }

    pcf_policyauth_free_qos_target_decision(QosDecisionList);
    OGS_SESSION_DATA_FREE(&session_data);

    ogs_info("[PolicyAuth-QoS] PCF notify SMF OK [%s:%d] qfi=%d 5qi=%d",
            pcf_ue_sm->supi, sess->psi, qfi, five_qi);

    return true;
}

bool pcf_npcf_am_policy_control_handle_create(pcf_ue_am_t *pcf_ue_am,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *message)
{
    bool rc;
    int r;

    OpenAPI_policy_association_request_t *PolicyAssociationRequest = NULL;
    OpenAPI_guami_t *Guami = NULL;
    OpenAPI_lnode_t *node = NULL;

    uint64_t supported_features = 0;

    ogs_sbi_server_t *server = NULL;
    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(pcf_ue_am);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);
    ogs_assert(message);

    PolicyAssociationRequest = message->PolicyAssociationRequest;
    if (!PolicyAssociationRequest) {
        ogs_error("[%s] No PolicyAssociationRequest", pcf_ue_am->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "[%s] No PolicyAssociationRequest", pcf_ue_am->supi,
                NULL));
        return false;
    }

    if (!PolicyAssociationRequest->notification_uri) {
        ogs_error("[%s] No notificationUri", pcf_ue_am->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No notificationUri", pcf_ue_am->supi, NULL));
        return false;
    }

    if (!PolicyAssociationRequest->supi) {
        ogs_error("[%s] No supi", pcf_ue_am->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No supi", pcf_ue_am->supi, NULL));
        return false;
    }

    if (!PolicyAssociationRequest->supp_feat) {
        ogs_error("[%s] No suppFeat", pcf_ue_am->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "No suppFeat", pcf_ue_am->supi, NULL));
        return false;
    }

    rc = ogs_sbi_getaddr_from_uri(&scheme, &fqdn, &fqdn_port, &addr, &addr6,
            PolicyAssociationRequest->notification_uri);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        ogs_error("[%s] Invalid URI [%s]",
                pcf_ue_am->supi, PolicyAssociationRequest->notification_uri);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                message, "[%s] Invalid URI", pcf_ue_am->supi, NULL));
        return false;
    }

    if (pcf_ue_am->notification_uri)
        ogs_free(pcf_ue_am->notification_uri);
    pcf_ue_am->notification_uri = ogs_strdup(
            PolicyAssociationRequest->notification_uri);
    ogs_assert(pcf_ue_am->notification_uri);

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("%s: ogs_sbi_client_add()", OGS_FUNC);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            ogs_error("%s: ogs_sbi_client_add() failed", OGS_FUNC);

            ogs_free(fqdn);
            ogs_freeaddrinfo(addr);
            ogs_freeaddrinfo(addr6);

            return false;
        }
    }
    OGS_SBI_SETUP_CLIENT(&pcf_ue_am->namf, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    supported_features =
        ogs_uint64_from_string_hexadecimal(
                PolicyAssociationRequest->supp_feat);
    pcf_ue_am->am_policy_control_features &= supported_features;

    if (PolicyAssociationRequest->gpsi) {
        if (pcf_ue_am->gpsi)
            ogs_free(pcf_ue_am->gpsi);
        pcf_ue_am->gpsi = ogs_strdup(PolicyAssociationRequest->gpsi);
    }

    pcf_ue_am->access_type = PolicyAssociationRequest->access_type;

    if (PolicyAssociationRequest->pei) {
        if (pcf_ue_am->pei)
            ogs_free(pcf_ue_am->pei);
        pcf_ue_am->pei = ogs_strdup(PolicyAssociationRequest->pei);
    }

    Guami = PolicyAssociationRequest->guami;
    if (Guami && Guami->amf_id &&
        Guami->plmn_id && Guami->plmn_id->mnc && Guami->plmn_id->mcc) {
        ogs_sbi_parse_guami(&pcf_ue_am->guami, PolicyAssociationRequest->guami);
    }

    OpenAPI_list_for_each(PolicyAssociationRequest->allowed_snssais, node) {
        struct OpenAPI_snssai_s *Snssai = node->data;
        if (Snssai) {
            ogs_s_nssai_t s_nssai;
            s_nssai.sst = Snssai->sst;
            s_nssai.sd = ogs_s_nssai_sd_from_string(Snssai->sd);

            pcf_metrics_inst_by_slice_add(&pcf_ue_am->guami.plmn_id,
                    &s_nssai, PCF_METR_CTR_PA_POLICYAMASSOREQ, 1);
        } else {
            ogs_error("[%s] No Snssai", pcf_ue_am->supi);
        }
    }

    if (PolicyAssociationRequest->rat_type)
        pcf_ue_am->rat_type = PolicyAssociationRequest->rat_type;

    pcf_ue_am->policy_association_request =
        OpenAPI_policy_association_request_copy(
                pcf_ue_am->policy_association_request,
                message->PolicyAssociationRequest);

    if (PolicyAssociationRequest->ue_ambr)
        pcf_ue_am->subscribed_ue_ambr = OpenAPI_ambr_copy(
                pcf_ue_am->subscribed_ue_ambr,
                PolicyAssociationRequest->ue_ambr);

    if (ogs_sbi_supi_in_vplmn(pcf_ue_am->supi) == true) {
        /* Visited PLMN */
        OpenAPI_policy_association_t PolicyAssociation;

        ogs_sbi_message_t sendmsg;
        ogs_sbi_header_t header;
        ogs_sbi_response_t *response = NULL;

        memset(&PolicyAssociation, 0, sizeof(PolicyAssociation));
        PolicyAssociation.request = pcf_ue_am->policy_association_request;
        PolicyAssociation.supp_feat =
            ogs_uint64_to_string(pcf_ue_am->am_policy_control_features);
        ogs_assert(PolicyAssociation.supp_feat);

        memset(&header, 0, sizeof(header));
        header.service.name =
            (char *)OGS_SBI_SERVICE_NAME_NPCF_AM_POLICY_CONTROL;
        header.api.version = (char *)OGS_SBI_API_V1;
        header.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_POLICIES;
        header.resource.component[1] = pcf_ue_am->association_id;

        memset(&sendmsg, 0, sizeof(sendmsg));
        sendmsg.PolicyAssociation = &PolicyAssociation;
        sendmsg.http.location = ogs_sbi_server_uri(server, &header);

        response = ogs_sbi_build_response(
                &sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        ogs_free(sendmsg.http.location);

        ogs_free(PolicyAssociation.supp_feat);

        return true;
    } else {
        /* Home PLMN */
        r = pcf_ue_am_sbi_discover_and_send(OGS_SBI_SERVICE_TYPE_NUDR_DR, NULL,
                pcf_nudr_dr_build_query_am_data, pcf_ue_am, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);

        return (r == OGS_OK);
    }
}

bool pcf_npcf_smpolicycontrol_handle_create(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *message)
{
    bool rc;
    int status = 0;
    int r;
    char *strerror = NULL;
    pcf_ue_sm_t *pcf_ue_sm = NULL;

    OpenAPI_sm_policy_context_data_t *SmPolicyContextData = NULL;
    OpenAPI_plmn_id_nid_t *servingNetwork = NULL;
    OpenAPI_snssai_t *sliceInfo = NULL;

    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    char *dnn_oi = NULL;

    ogs_assert(sess);
    pcf_ue_sm = pcf_ue_sm_find_by_id(sess->pcf_ue_sm_id);
    ogs_assert(stream);
    ogs_assert(message);

    SmPolicyContextData = message->SmPolicyContextData;
    if (!SmPolicyContextData) {
        strerror = ogs_msprintf("[%s:%d] No SmPolicyContextData",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->supi) {
        strerror = ogs_msprintf("[%s:%d] No supi", pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->pdu_session_id) {
        strerror = ogs_msprintf("[%s:%d] No pduSessionId",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->pdu_session_type) {
        strerror = ogs_msprintf("[%s:%d] No pduSessionType",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->dnn) {
        strerror = ogs_msprintf("[%s:%d] No dnn", pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->notification_uri) {
        strerror = ogs_msprintf("[%s:%d] No notificationUri",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!SmPolicyContextData->ipv4_address &&
        !SmPolicyContextData->ipv6_address_prefix) {
        strerror = ogs_msprintf(
                "[%s:%d] No IPv4 address[%p] or IPv6 prefix[%p]",
                pcf_ue_sm->supi, sess->psi,
                SmPolicyContextData->ipv4_address,
                SmPolicyContextData->ipv6_address_prefix);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    sliceInfo = SmPolicyContextData->slice_info;
    if (!sliceInfo) {
        strerror = ogs_msprintf("[%s:%d] No sliceInfo",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    servingNetwork = SmPolicyContextData->serving_network;
    if (servingNetwork) {
        if (!servingNetwork->mcc) {
            strerror = ogs_msprintf("[%s:%d] No servingNetwork->mcc",
                    pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }
        if (!servingNetwork->mnc) {
            strerror = ogs_msprintf("[%s:%d] No servingNetwork->mnc",
                    pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }
    } else {
        ogs_warn("No servingNetwork");
    }

    rc = ogs_sbi_getaddr_from_uri(&scheme, &fqdn, &fqdn_port, &addr, &addr6,
            SmPolicyContextData->notification_uri);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        strerror = ogs_msprintf("[%s:%d] Invalid URI [%s]",
                pcf_ue_sm->supi, sess->psi,
                SmPolicyContextData->notification_uri);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (SmPolicyContextData->gpsi) {
        if (pcf_ue_sm->gpsi)
            ogs_free(pcf_ue_sm->gpsi);
        pcf_ue_sm->gpsi = ogs_strdup(SmPolicyContextData->gpsi);
    }

    if (SmPolicyContextData->supp_feat) {
        uint64_t supported_features =
            ogs_uint64_from_string_hexadecimal(
                    SmPolicyContextData->supp_feat);
        sess->smpolicycontrol_features &= supported_features;
    } else {
        sess->smpolicycontrol_features = 0;
    }

    sess->pdu_session_type = SmPolicyContextData->pdu_session_type;

    /* Serving PLMN & Home PLMN */
    if (servingNetwork) {
        sess->serving.presence = true;
        ogs_sbi_parse_plmn_id_nid(&sess->serving.plmn_id, servingNetwork);

        sess->home.presence = true;
        memcpy(&sess->home.plmn_id, &sess->serving.plmn_id, OGS_PLMN_ID_LEN);
    }

    /*
     * TS29.512
     * 5 Npcf_SMPolicyControl Service API
     * 5.6 Data Model
     * 5.6.2 Structured data types
     * Table 5.6.2.3-1: Definition of type SmPolicyContextData
     *
     * NAME: dnn
     * Data type: Dnn
     * P: M
     * Cardinality: 1
     * The DNN of the PDU session, a full DNN with both the Network Identifier
     * and Operator Identifier, or a DNN with the Network Identifier only
     */
    dnn_oi = ogs_dnn_oi_from_fqdn(SmPolicyContextData->dnn);

    if (dnn_oi) {
        char dnn_ni[OGS_MAX_DNN_LEN+1];
        uint16_t mcc = 0, mnc = 0;

        ogs_assert(dnn_oi > SmPolicyContextData->dnn);

        ogs_cpystrn(dnn_ni, SmPolicyContextData->dnn,
            ogs_min(OGS_MAX_DNN_LEN, dnn_oi - SmPolicyContextData->dnn));

        if (sess->dnn)
            ogs_free(sess->dnn);
        sess->dnn = ogs_strdup(dnn_ni);
        ogs_assert(sess->dnn);

        if (sess->full_dnn)
            ogs_free(sess->full_dnn);
        sess->full_dnn = ogs_strdup(SmPolicyContextData->dnn);
        ogs_assert(sess->full_dnn);

        mcc = ogs_plmn_id_mcc_from_fqdn(sess->full_dnn);
        mnc = ogs_plmn_id_mnc_from_fqdn(sess->full_dnn);

        /*
         * To generate the Home PLMN ID of the SMF-UE,
         * the length of the MNC is obtained
         * by comparing the MNC part of the SUPI and full-DNN.
         */
        if (mcc && mnc &&
            strncmp(pcf_ue_sm->supi, "imsi-", strlen("imsi-")) == 0) {
            int mnc_len = 0;
            char buf[OGS_PLMNIDSTRLEN];

            ogs_snprintf(buf, OGS_PLMNIDSTRLEN, "%03d%02d", mcc, mnc);
            if (strncmp(pcf_ue_sm->supi + 5, buf, strlen(buf)) == 0)
                mnc_len = 2;

            ogs_snprintf(buf, OGS_PLMNIDSTRLEN, "%03d%03d", mcc, mnc);
            if (strncmp(pcf_ue_sm->supi + 5, buf, strlen(buf)) == 0)
                mnc_len = 3;

            /* Change Home PLMN for VPLMN */
            if (mnc_len == 2 || mnc_len == 3) {
                if (sess->home.presence == true)
                    ogs_plmn_id_build(&sess->home.plmn_id, mcc, mnc, mnc_len);
            }
        }
    } else {
        if (sess->dnn)
            ogs_free(sess->dnn);
        sess->dnn = ogs_strdup(SmPolicyContextData->dnn);
        ogs_assert(sess->dnn);

        if (sess->full_dnn)
            ogs_free(sess->full_dnn);
        sess->full_dnn = NULL;
    }

    if (sess->notification_uri)
        ogs_free(sess->notification_uri);
    sess->notification_uri = ogs_strdup(SmPolicyContextData->notification_uri);
    ogs_assert(sess->notification_uri);

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("%s: ogs_sbi_client_add()", OGS_FUNC);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            strerror = ogs_msprintf("%s: ogs_sbi_client_add() failed",
                    OGS_FUNC);
            status = OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
            ogs_freeaddrinfo(addr);
            goto cleanup;
        }
    }
    OGS_SBI_SETUP_CLIENT(&sess->nsmf, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    if (SmPolicyContextData->ipv4_address)
        ogs_assert(true ==
            pcf_sess_set_ipv4addr(sess, SmPolicyContextData->ipv4_address));
    if (SmPolicyContextData->ipv6_address_prefix)
        ogs_assert(true ==
            pcf_sess_set_ipv6prefix(
                sess, SmPolicyContextData->ipv6_address_prefix));

    if (SmPolicyContextData->ipv4_frame_route_list) {
        OpenAPI_lnode_t *node = NULL;

        OpenAPI_clear_and_free_string_list(sess->ipv4_frame_route_list);
        sess->ipv4_frame_route_list = OpenAPI_list_create();
        OpenAPI_list_for_each(
                SmPolicyContextData->ipv4_frame_route_list, node) {
            if (!node->data)
                continue;
            OpenAPI_list_add(
                    sess->ipv4_frame_route_list, ogs_strdup(node->data));
        }
    }

    if (SmPolicyContextData->ipv6_frame_route_list) {
        OpenAPI_lnode_t *node = NULL;

        OpenAPI_clear_and_free_string_list(sess->ipv6_frame_route_list);
        sess->ipv6_frame_route_list = OpenAPI_list_create();
        OpenAPI_list_for_each(
                SmPolicyContextData->ipv6_frame_route_list, node) {
            if (!node->data)
                continue;
            OpenAPI_list_add(
                    sess->ipv6_frame_route_list, ogs_strdup(node->data));
        }
    }

    sess->s_nssai.sst = sliceInfo->sst;
    sess->s_nssai.sd = ogs_s_nssai_sd_from_string(sliceInfo->sd);

    pcf_metrics_inst_by_slice_add(
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, PCF_METR_GAUGE_PA_SESSIONNBR, 1);
    pcf_metrics_inst_by_slice_add(
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, PCF_METR_CTR_PA_POLICYSMASSOREQ, 1);

    if (SmPolicyContextData->subs_sess_ambr)
        sess->subscribed_sess_ambr = OpenAPI_ambr_copy(
            sess->subscribed_sess_ambr, SmPolicyContextData->subs_sess_ambr);

    if (SmPolicyContextData->subs_def_qos)
        sess->subscribed_default_qos = OpenAPI_subscribed_default_qos_copy(
            sess->subscribed_default_qos, SmPolicyContextData->subs_def_qos);

    if (ogs_sbi_supi_in_vplmn(pcf_ue_sm->supi) == true) {
        /* Visited PLMN */
        r = pcf_sess_sbi_discover_and_send(
                    OGS_SBI_SERVICE_TYPE_NBSF_MANAGEMENT, NULL,
                    pcf_nbsf_management_build_register,
                    sess, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);

        return (r == OGS_OK);
    } else {
        /* Home PLMN */
        r = pcf_sess_sbi_discover_and_send(
                OGS_SBI_SERVICE_TYPE_NUDR_DR, NULL,
                pcf_nudr_dr_build_query_sm_data, sess, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);

        return (r == OGS_OK);
    }

cleanup:
    ogs_assert(status);
    ogs_assert(strerror);
    ogs_error("%s", strerror);
    /*
     * TS29.512
     * 4.2.2.2 SM Policy Association establishment 
     *
     * If the PCF is, due to incomplete, erroneous or missing
     * information (e.g. QoS, RAT type, subscriber information)
     * not able to provision a policy decision as response to
     * the request for PCC rules by the SMF, the PCF may reject
     * the request and include in an HTTP "400 Bad Request"
     * response message the "cause" attribute of the ProblemDetails
     * data structure set to "ERROR_INITIAL_PARAMETERS". 
     */
    ogs_assert(true ==
            ogs_sbi_server_send_error(stream, status, message,
                    strerror, NULL, "ERROR_INITIAL_PARAMETERS"));
    ogs_free(strerror);

    return false;
}

bool pcf_npcf_smpolicycontrol_handle_delete(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *message)
{
    int r;
    int status = 0;
    char *strerror = NULL;
    pcf_ue_sm_t *pcf_ue_sm = NULL;
    pcf_app_t *app_session = NULL;

    OpenAPI_sm_policy_delete_data_t *SmPolicyDeleteData = NULL;

    ogs_assert(sess);
    pcf_ue_sm = pcf_ue_sm_find_by_id(sess->pcf_ue_sm_id);
    ogs_assert(stream);
    ogs_assert(message);

    SmPolicyDeleteData = message->SmPolicyDeleteData;
    if (!SmPolicyDeleteData) {
        strerror = ogs_msprintf("[%s:%d] No SmPolicyDeleteData",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    ogs_list_for_each(&sess->app_list, app_session) {
        pcf_sbi_send_policyauthorization_terminate_notify(app_session);
    }

    if (pcf_sessions_number_by_snssai_and_dnn(
                pcf_ue_sm, &sess->s_nssai, sess->dnn) > 1) {
        ogs_expect(true ==
                ogs_sbi_send_response(stream, OGS_SBI_HTTP_STATUS_NO_CONTENT));
    } else if (sess->binding.resource_uri) {
        r = pcf_sess_sbi_discover_and_send(
                OGS_SBI_SERVICE_TYPE_NBSF_MANAGEMENT, NULL,
                pcf_nbsf_management_build_de_register, sess, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
    } else {
        ogs_expect(true ==
                ogs_sbi_send_response(stream, OGS_SBI_HTTP_STATUS_NO_CONTENT));
    }

    return true;

cleanup:
    ogs_assert(status);
    ogs_assert(strerror);
    ogs_error("%s", strerror);
    ogs_assert(true ==
        ogs_sbi_server_send_error(stream, status, message, strerror, NULL,
                NULL));
    ogs_free(strerror);

    return false;
}

bool pcf_npcf_policyauthorization_handle_create(pcf_sess_t *sess,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    bool rc;
    int i, j, rv, status = 0;
    char *strerror = NULL;
    pcf_ue_sm_t *pcf_ue_sm = NULL;
    pcf_app_t *app_session = NULL;

    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    OpenAPI_app_session_context_t *AppSessionContext = NULL;
    OpenAPI_app_session_context_req_data_t *AscReqData = NULL;

    uint64_t supported_features = 0;

    ogs_sbi_server_t *server = NULL;
    ogs_sbi_header_t header;
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_session_data_t session_data;

    ogs_ims_data_t ims_data;
    ogs_media_component_t *media_component = NULL;
    ogs_media_sub_component_t *sub = NULL;

    OpenAPI_list_t *MediaComponentList = NULL;
    OpenAPI_map_t *MediaComponentMap = NULL;
    OpenAPI_media_component_t *MediaComponent = NULL;

    OpenAPI_list_t *SubComponentList = NULL;
    OpenAPI_map_t *SubComponentMap = NULL;
    OpenAPI_media_sub_component_t *SubComponent = NULL;

    OpenAPI_list_t *fDescList = NULL;

    OpenAPI_sm_policy_decision_t SmPolicyDecision;

    OpenAPI_list_t *PccRuleList = NULL;
    OpenAPI_map_t *PccRuleMap = NULL;
    OpenAPI_pcc_rule_t *PccRule = NULL;

    OpenAPI_list_t *QosDecisionList = NULL;
    OpenAPI_map_t *QosDecisionMap = NULL;
    OpenAPI_qos_data_t *QosData = NULL;

    OpenAPI_lnode_t *node = NULL, *node2 = NULL, *node3 = NULL;

    ogs_assert(sess);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    pcf_ue_sm = pcf_ue_sm_find_by_id(sess->pcf_ue_sm_id);
    pcf_policyauth_log_api_ingress(
            "POST", sess, pcf_ue_sm, NULL, recvmsg, false);

    ogs_assert(pcf_ue_sm);

    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    memset(&ims_data, 0, sizeof(ims_data));
    memset(&session_data, 0, sizeof(ogs_session_data_t));

    AppSessionContext = recvmsg->AppSessionContext;
    if (!AppSessionContext) {
        strerror = ogs_msprintf("[%s:%d] No AppSessionContext",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    AscReqData = AppSessionContext->asc_req_data;
    if (!AscReqData) {
        strerror = ogs_msprintf("[%s:%d] No AscReqData",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!AscReqData->supp_feat) {
        strerror = ogs_msprintf("[%s:%d] No AscReqData->suppFeat",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (!AscReqData->notif_uri) {
        strerror = ogs_msprintf("[%s:%d] No AscReqData->notifUri",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    /*
     * Lab QoS-target via standard Policy Authorization (afAppId 5GC-QOS:...)
     */
    if (AscReqData->af_app_id) {
        uint8_t target_qfi = 0;
        int target_5qi = 0;
        uint64_t gbr_dl = 0, gbr_ul = 0, mbr_dl = 0, mbr_ul = 0;
        bool has_gbr = false, has_mbr = false;

        if (pcf_policyauth_parse_qos_target_af_app_id(
                    AscReqData->af_app_id, &target_qfi, &target_5qi,
                    &gbr_dl, &gbr_ul, &mbr_dl, &mbr_ul, &has_gbr, &has_mbr)) {

            pcf_policyauth_log_qos_target("AF POST app-session", pcf_ue_sm, sess,
                    AscReqData->af_app_id, target_qfi, target_5qi,
                    gbr_dl, gbr_ul, mbr_dl, mbr_ul, has_gbr, has_mbr);

            rc = ogs_sbi_getaddr_from_uri(&scheme, &fqdn, &fqdn_port,
                    &addr, &addr6, AscReqData->notif_uri);
            if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
                strerror = ogs_msprintf("[%s:%d] Invalid URI [%s]",
                        pcf_ue_sm->supi, sess->psi, AscReqData->notif_uri);
                status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
                goto cleanup;
            }

            app_session = pcf_app_add(sess);
            ogs_assert(app_session);

            if (app_session->notif_uri)
                ogs_free(app_session->notif_uri);
            app_session->notif_uri = ogs_strdup(AscReqData->notif_uri);
            ogs_assert(app_session->notif_uri);

            client = ogs_sbi_client_find(
                    scheme, fqdn, fqdn_port, addr, addr6);
            if (!client) {
                client = ogs_sbi_client_add(
                        scheme, fqdn, fqdn_port, addr, addr6);
                if (!client) {
                    strerror = ogs_msprintf(
                            "%s: ogs_sbi_client_add() failed", OGS_FUNC);
                    status = OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
                    ogs_freeaddrinfo(addr);
                    goto cleanup;
                }
            }
            OGS_SBI_SETUP_CLIENT(&app_session->naf, client);

            ogs_free(fqdn);
            ogs_freeaddrinfo(addr);
            ogs_freeaddrinfo(addr6);

            if (!pcf_policyauth_send_qos_target_notify(
                        sess, pcf_ue_sm, target_qfi, target_5qi,
                        gbr_dl, gbr_ul, mbr_dl, mbr_ul, has_gbr, has_mbr)) {
                strerror = ogs_msprintf("[%s:%d] QoS target notify failed",
                        pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
                goto cleanup;
            }

            memset(&sendmsg, 0, sizeof(sendmsg));
            memset(&header, 0, sizeof(header));
            header.service.name =
                (char *)OGS_SBI_SERVICE_NAME_NPCF_POLICYAUTHORIZATION;
            header.api.version = (char *)OGS_SBI_API_V1;
            header.resource.component[0] =
                (char *)OGS_SBI_RESOURCE_NAME_APP_SESSIONS;
            header.resource.component[1] =
                (char *)app_session->app_session_id;
            sendmsg.http.location = ogs_sbi_server_uri(server, &header);
            ogs_assert(sendmsg.http.location);

            sendmsg.AppSessionContext = recvmsg->AppSessionContext;

            response = ogs_sbi_build_response(
                    &sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
            ogs_assert(response);
            ogs_assert(true == ogs_sbi_server_send_response(stream, response));

            ogs_free(sendmsg.http.location);
            return true;
        }
    }

    if (!AscReqData->med_components) {
        strerror = ogs_msprintf("[%s:%d] No AscReqData->MediaCompoenent",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    rc = ogs_sbi_getaddr_from_uri(&scheme, &fqdn, &fqdn_port, &addr, &addr6,
            AscReqData->notif_uri);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        strerror = ogs_msprintf("[%s:%d] Invalid URI [%s]",
                pcf_ue_sm->supi, sess->psi, AscReqData->notif_uri);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    supported_features = ogs_uint64_from_string_hexadecimal(
            AscReqData->supp_feat);
    sess->policyauthorization_features &= supported_features;

    if (sess->policyauthorization_features != supported_features) {
        ogs_free(AscReqData->supp_feat);
        AscReqData->supp_feat =
            ogs_uint64_to_string(sess->policyauthorization_features);
        ogs_assert(AscReqData->supp_feat);
    }

    MediaComponentList = AscReqData->med_components;
    OpenAPI_list_for_each(MediaComponentList, node) {
        MediaComponentMap = node->data;
        if (MediaComponentMap) {
            MediaComponent = MediaComponentMap->value;
            if (MediaComponent) {
                if (ims_data.num_of_media_component >=
                        OGS_ARRAY_SIZE(ims_data.media_component)) {
                    ogs_error("OVERFLOW ims_data.num_of_media_component "
                            "[%d:%d:%d]",
                            ims_data.num_of_media_component,
                            OGS_MAX_NUM_OF_MEDIA_COMPONENT,
                            (int)OGS_ARRAY_SIZE(ims_data.media_component));
                    break;
                }
                media_component = &ims_data.
                    media_component[ims_data.num_of_media_component];
                media_component->media_component_number =
                    MediaComponent->med_comp_n;
                media_component->media_type = MediaComponent->med_type;
                if (MediaComponent->mar_bw_dl)
                    media_component->max_requested_bandwidth_dl =
                        ogs_sbi_bitrate_from_string(MediaComponent->mar_bw_dl);
                if (MediaComponent->mar_bw_ul)
                    media_component->max_requested_bandwidth_ul =
                        ogs_sbi_bitrate_from_string(MediaComponent->mar_bw_ul);
                if (MediaComponent->mir_bw_dl)
                    media_component->min_requested_bandwidth_dl =
                        ogs_sbi_bitrate_from_string(MediaComponent->mir_bw_dl);
                if (MediaComponent->mir_bw_ul)
                    media_component->min_requested_bandwidth_ul =
                        ogs_sbi_bitrate_from_string(MediaComponent->mir_bw_ul);
                if (MediaComponent->rr_bw)
                    media_component->rr_bandwidth =
                        ogs_sbi_bitrate_from_string(MediaComponent->rr_bw);
                if (MediaComponent->rs_bw)
                    media_component->rs_bandwidth =
                        ogs_sbi_bitrate_from_string(MediaComponent->rs_bw);
                media_component->flow_status = MediaComponent->f_status;

                SubComponentList = MediaComponent->med_sub_comps;
                OpenAPI_list_for_each(SubComponentList, node2) {
                    if (media_component->num_of_sub >=
                            OGS_ARRAY_SIZE(media_component->sub)) {
                        ogs_error("OVERFLOW media_component->num_of_sub "
                                "[%d:%d:%d]",
                                media_component->num_of_sub,
                                OGS_MAX_NUM_OF_MEDIA_SUB_COMPONENT,
                                (int)OGS_ARRAY_SIZE(media_component->sub));
                        break;
                    }
                    sub = &media_component->sub[media_component->num_of_sub];

                    SubComponentMap = node2->data;
                    if (SubComponentMap) {
                        SubComponent = SubComponentMap->value;
                        if (SubComponent) {
                            sub->flow_number = SubComponent->f_num;
                            sub->flow_usage = SubComponent->flow_usage;

                            fDescList = SubComponent->f_descs;
                            OpenAPI_list_for_each(fDescList, node3) {
                                ogs_flow_t *flow = NULL;

                                if (sub->num_of_flow >=
                                        OGS_ARRAY_SIZE(sub->flow)) {
                                    ogs_error(
                                        "OVERFLOW sub->num_of_flow [%d:%d:%d]",
                                        sub->num_of_flow,
                                        OGS_MAX_NUM_OF_FLOW_IN_MEDIA_SUB_COMPONENT,
                                        (int)OGS_ARRAY_SIZE(sub->flow));
                                    break;
                                }
                                flow = &sub->flow[sub->num_of_flow];
                                if (node3->data) {
                                    flow->description = ogs_strdup(node3->data);
                                    ogs_assert(flow->description);

                                    sub->num_of_flow++;
                                }
                            }
                            media_component->num_of_sub++;
                        }
                    }
                }
                ims_data.num_of_media_component++;
            }
        }
    }

    app_session = pcf_app_add(sess);
    ogs_assert(app_session);

    if (app_session->notif_uri)
        ogs_free(app_session->notif_uri);
    app_session->notif_uri = ogs_strdup(AscReqData->notif_uri);
    ogs_assert(app_session->notif_uri);

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("%s: ogs_sbi_client_add()", OGS_FUNC);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            strerror = ogs_msprintf("%s: ogs_sbi_client_add() failed",
                    OGS_FUNC);
            status = OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
            ogs_freeaddrinfo(addr);
            goto cleanup;
        }
    }
    OGS_SBI_SETUP_CLIENT(&app_session->naf, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    rv = pcf_get_session_data(
            pcf_ue_sm->supi,
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, sess->dnn, &session_data, 0);
    if (rv != OGS_OK) {
        strerror = ogs_msprintf("[%s:%d] Cannot find SUPI in DB",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_NOT_FOUND;
        goto cleanup;
    }

    memset(&SmPolicyDecision, 0, sizeof(SmPolicyDecision));

    PccRuleList = OpenAPI_list_create();
    ogs_assert(PccRuleList);

    QosDecisionList = OpenAPI_list_create();
    ogs_assert(QosDecisionList);

    for (i = 0; i < ims_data.num_of_media_component; i++) {
        int flow_presence = 0;

        ogs_pcc_rule_t *pcc_rule = NULL;
        ogs_pcc_rule_t *db_pcc_rule = NULL;
        uint8_t qos_index = 0;
        ogs_media_component_t *media_component = &ims_data.media_component[i];

        if (media_component->media_type == OpenAPI_media_type_NULL) {
            strerror = ogs_msprintf("[%s:%d] Media-Type is Required",
                    pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }

        switch(media_component->media_type) {
        case OpenAPI_media_type_AUDIO:
            qos_index = OGS_QOS_INDEX_1;
            break;
        case OpenAPI_media_type_VIDEO:
            qos_index = OGS_QOS_INDEX_2;
            break;
        case OpenAPI_media_type_CONTROL:
            qos_index = OGS_QOS_INDEX_5;
            break;
        default:
            strerror = ogs_msprintf("[%s:%d] Unknown Media-Type [%d]",
                    pcf_ue_sm->supi, sess->psi, media_component->media_type);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }

        for (j = 0; j < session_data.num_of_pcc_rule; j++) {
            if (session_data.pcc_rule[j].qos.index == qos_index) {
                db_pcc_rule = &session_data.pcc_rule[j];
                break;
            }
        }

        if (!db_pcc_rule &&
            (media_component->media_type == OpenAPI_media_type_CONTROL)) {
            /*
             * Check for default bearer for IMS signalling
             * QCI 5 and ARP 1
             */
            if (session_data.session.qos.index != OGS_QOS_INDEX_5 ||
                session_data.session.qos.arp.priority_level != 1) {
                strerror = ogs_msprintf("[%s:%d] CHECK WEBUI : "
                    "Even the Default Bearer(QCI:%d,ARP:%d) "
                    "cannot support IMS signalling.",
                    pcf_ue_sm->supi, sess->psi,
                    session_data.session.qos.index,
                    session_data.session.qos.arp.priority_level);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            } else {
                continue;
            }
        }

        if (!db_pcc_rule) {
            strerror = ogs_msprintf("[%s:%d] CHECK WEBUI : "
                "No PCC Rule in DB [QoS Index:%d] - "
                "Please add PCC Rule using WEBUI",
                pcf_ue_sm->supi, sess->psi, qos_index);
            status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
            goto cleanup;
        }

        for (j = 0; j < app_session->num_of_pcc_rule; j++) {
            if (app_session->pcc_rule[j].qos.index == qos_index) {
                pcc_rule = &app_session->pcc_rule[j];
                break;
            }
        }

        if (!pcc_rule) {
            pcc_rule = &app_session->pcc_rule[app_session->num_of_pcc_rule];
            ogs_assert(pcc_rule);

            pcc_rule->id = ogs_msprintf("%s-a%s",
                            db_pcc_rule->id, app_session->app_session_id);
            ogs_assert(pcc_rule->id);

            memcpy(&pcc_rule->qos, &db_pcc_rule->qos, sizeof(ogs_qos_t));

            pcc_rule->flow_status = db_pcc_rule->flow_status;
            pcc_rule->precedence = db_pcc_rule->precedence;

            /* Install Flow */
            flow_presence = 1;
            rv = ogs_pcc_rule_install_flow_from_media(
                    pcc_rule, media_component);
            if (rv != OGS_OK) {
                strerror = ogs_msprintf("[%s:%d] install_flow() failed",
                    pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            }

            app_session->num_of_pcc_rule++;

        } else {
            int count = 0;

            /* Check Flow */
            count = ogs_pcc_rule_num_of_flow_equal_to_media(
                    pcc_rule, media_component);
            if (count == -1) {
                strerror = ogs_msprintf("[%s:%d] matched_flow() failed",
                    pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            }

            if (pcc_rule->num_of_flow != count) {
                /* Re-install Flow */
                flow_presence = 1;
                rv = ogs_pcc_rule_install_flow_from_media(
                        pcc_rule, media_component);
                if (rv != OGS_OK) {
                    strerror = ogs_msprintf("[%s:%d] re-install_flow() failed",
                        pcf_ue_sm->supi, sess->psi);
                    status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                    goto cleanup;
                }
            }
        }

        /* Update QoS */
        rv = ogs_pcc_rule_update_qos_from_media(pcc_rule, media_component);
        if (rv != OGS_OK) {
            strerror = ogs_msprintf("[%s:%d] update_qos() failed",
                pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
            goto cleanup;
        }

        /* if we failed to get QoS from IMS, apply WEBUI QoS */
        if (pcc_rule->qos.mbr.downlink == 0)
            pcc_rule->qos.mbr.downlink = db_pcc_rule->qos.mbr.downlink;
        if (pcc_rule->qos.mbr.uplink == 0)
            pcc_rule->qos.mbr.uplink = db_pcc_rule->qos.mbr.uplink;
        if (pcc_rule->qos.gbr.downlink == 0)
            pcc_rule->qos.gbr.downlink = db_pcc_rule->qos.gbr.downlink;
        if (pcc_rule->qos.gbr.uplink == 0)
            pcc_rule->qos.gbr.uplink = db_pcc_rule->qos.gbr.uplink;

        /**************************************************************
         * Build PCC Rule & QoS Decision
         *************************************************************/
        PccRule = ogs_sbi_build_pcc_rule(pcc_rule, flow_presence);
        ogs_assert(PccRule->pcc_rule_id);

        PccRuleMap = OpenAPI_map_create(PccRule->pcc_rule_id, PccRule);
        ogs_assert(PccRuleMap);

        OpenAPI_list_add(PccRuleList, PccRuleMap);

        QosData = ogs_sbi_build_qos_data(pcc_rule);
        ogs_assert(QosData);
        ogs_assert(QosData->qos_id);

        QosDecisionMap = OpenAPI_map_create(QosData->qos_id, QosData);
        ogs_assert(QosDecisionMap);

        OpenAPI_list_add(QosDecisionList, QosDecisionMap);
    }

    if (PccRuleList->count)
        SmPolicyDecision.pcc_rules = PccRuleList;

    if (QosDecisionList->count)
        SmPolicyDecision.qos_decs = QosDecisionList;

    memset(&sendmsg, 0, sizeof(sendmsg));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NPCF_POLICYAUTHORIZATION;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_APP_SESSIONS;
    header.resource.component[1] = (char *)app_session->app_session_id;
    sendmsg.http.location = ogs_sbi_server_uri(server, &header);
    ogs_assert(sendmsg.http.location);

    sendmsg.AppSessionContext = recvmsg->AppSessionContext;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    ogs_free(sendmsg.http.location);

    if (PccRuleList->count || QosDecisionList->count) {
        ogs_assert(true == pcf_sbi_send_smpolicycontrol_update_notify(
                                sess, &SmPolicyDecision));
    }

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            PccRule = PccRuleMap->value;
            if (PccRule)
                ogs_sbi_free_pcc_rule(PccRule);
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    ogs_ims_data_free(&ims_data);
    OGS_SESSION_DATA_FREE(&session_data);

    return true;

cleanup:
    ogs_assert(status);
    ogs_assert(strerror);
    ogs_error("%s", strerror);
    ogs_assert(true ==
        ogs_sbi_server_send_error(stream, status, recvmsg, strerror, NULL,
                NULL));
    ogs_free(strerror);

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            PccRule = PccRuleMap->value;
            if (PccRule)
                ogs_sbi_free_pcc_rule(PccRule);
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    ogs_ims_data_free(&ims_data);
    OGS_SESSION_DATA_FREE(&session_data);

    return false;
}

bool pcf_npcf_policyauthorization_handle_update(
        pcf_sess_t *sess, pcf_app_t *app_session,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int i, j, rv, status = 0;
    char *strerror = NULL;
    pcf_ue_sm_t *pcf_ue_sm = NULL;

    OpenAPI_app_session_context_update_data_patch_t
        *AppSessionContextUpdateDataPatch = NULL;
    OpenAPI_app_session_context_update_data_t *AscUpdateData = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_session_data_t session_data;

    ogs_ims_data_t ims_data;
    ogs_media_component_t *media_component = NULL;
    ogs_media_sub_component_t *sub = NULL;

    OpenAPI_list_t *MediaComponentList = NULL;
    OpenAPI_map_t *MediaComponentMap = NULL;
    OpenAPI_media_component_rm_t *MediaComponent = NULL;

    OpenAPI_list_t *SubComponentList = NULL;
    OpenAPI_map_t *SubComponentMap = NULL;
    OpenAPI_media_sub_component_rm_t *SubComponent = NULL;

    OpenAPI_list_t *fDescList = NULL;

    OpenAPI_sm_policy_decision_t SmPolicyDecision;

    OpenAPI_list_t *PccRuleList = NULL;
    OpenAPI_map_t *PccRuleMap = NULL;
    OpenAPI_pcc_rule_t *PccRule = NULL;

    OpenAPI_list_t *QosDecisionList = NULL;
    OpenAPI_map_t *QosDecisionMap = NULL;
    OpenAPI_qos_data_t *QosData = NULL;

    OpenAPI_lnode_t *node = NULL, *node2 = NULL, *node3 = NULL;

    ogs_assert(sess);
    ogs_assert(app_session);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    pcf_ue_sm = pcf_ue_sm_find_by_id(sess->pcf_ue_sm_id);
    pcf_policyauth_log_api_ingress(
            "PATCH", sess, pcf_ue_sm, app_session, recvmsg, true);

    ogs_assert(pcf_ue_sm);

    memset(&ims_data, 0, sizeof(ims_data));
    memset(&session_data, 0, sizeof(ogs_session_data_t));

    AppSessionContextUpdateDataPatch =
        recvmsg->AppSessionContextUpdateDataPatch;
    if (!AppSessionContextUpdateDataPatch) {
        strerror = ogs_msprintf("[%s:%d] No AppSessionContextUpdateDataPatch",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    AscUpdateData = AppSessionContextUpdateDataPatch->asc_req_data;
    if (!AscUpdateData) {
        strerror = ogs_msprintf("[%s:%d] No AscUpdateData",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    if (AscUpdateData->af_app_id) {
        uint8_t target_qfi = 0;
        int target_5qi = 0;
        uint64_t gbr_dl = 0, gbr_ul = 0, mbr_dl = 0, mbr_ul = 0;
        bool has_gbr = false, has_mbr = false;

        if (pcf_policyauth_parse_qos_target_af_app_id(
                    AscUpdateData->af_app_id, &target_qfi, &target_5qi,
                    &gbr_dl, &gbr_ul, &mbr_dl, &mbr_ul, &has_gbr, &has_mbr)) {

            pcf_policyauth_log_qos_target("AF PATCH app-session", pcf_ue_sm, sess,
                    AscUpdateData->af_app_id, target_qfi, target_5qi,
                    gbr_dl, gbr_ul, mbr_dl, mbr_ul, has_gbr, has_mbr);

            if (!pcf_policyauth_send_qos_target_notify(
                        sess, pcf_ue_sm, target_qfi, target_5qi,
                        gbr_dl, gbr_ul, mbr_dl, mbr_ul, has_gbr, has_mbr)) {
                strerror = ogs_msprintf("[%s:%d] QoS target notify failed",
                        pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
                goto cleanup;
            }

            ogs_assert(true ==
                    ogs_sbi_send_http_status_no_content(stream));
            return true;
        }
    }

    if (!AscUpdateData->med_components) {
        strerror = ogs_msprintf("[%s:%d] No AscUpdateData->MediaCompoenent",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        goto cleanup;
    }

    MediaComponentList = AscUpdateData->med_components;
    OpenAPI_list_for_each(MediaComponentList, node) {
        MediaComponentMap = node->data;
        if (MediaComponentMap) {
            MediaComponent = MediaComponentMap->value;
            if (MediaComponent) {
                if (ims_data.num_of_media_component >=
                        OGS_ARRAY_SIZE(ims_data.media_component)) {
                    ogs_error("OVERFLOW ims_data.num_of_media_component "
                            "[%d:%d:%d]",
                            ims_data.num_of_media_component,
                            OGS_MAX_NUM_OF_MEDIA_COMPONENT,
                            (int)OGS_ARRAY_SIZE(ims_data.media_component));
                    break;
                }
                media_component = &ims_data.
                    media_component[ims_data.num_of_media_component];

                media_component->media_component_number =
                    MediaComponent->med_comp_n;
                media_component->media_type = MediaComponent->med_type;
                if (MediaComponent->mar_bw_dl)
                    media_component->max_requested_bandwidth_dl =
                        ogs_sbi_bitrate_from_string(MediaComponent->mar_bw_dl);
                if (MediaComponent->mar_bw_ul)
                    media_component->max_requested_bandwidth_ul =
                        ogs_sbi_bitrate_from_string(MediaComponent->mar_bw_ul);
                if (MediaComponent->mir_bw_dl)
                    media_component->min_requested_bandwidth_dl =
                        ogs_sbi_bitrate_from_string(MediaComponent->mir_bw_dl);
                if (MediaComponent->mir_bw_ul)
                    media_component->min_requested_bandwidth_ul =
                        ogs_sbi_bitrate_from_string(MediaComponent->mir_bw_ul);
                if (MediaComponent->rr_bw)
                    media_component->rr_bandwidth =
                        ogs_sbi_bitrate_from_string(MediaComponent->rr_bw);
                if (MediaComponent->rs_bw)
                    media_component->rs_bandwidth =
                        ogs_sbi_bitrate_from_string(MediaComponent->rs_bw);
                media_component->flow_status = MediaComponent->f_status;

                SubComponentList = MediaComponent->med_sub_comps;
                OpenAPI_list_for_each(SubComponentList, node2) {
                    if (media_component->num_of_sub >=
                            OGS_ARRAY_SIZE(media_component->sub)) {
                        ogs_error("OVERFLOW media_component->num_of_sub "
                                "[%d:%d:%d]",
                                media_component->num_of_sub,
                                OGS_MAX_NUM_OF_MEDIA_SUB_COMPONENT,
                                (int)OGS_ARRAY_SIZE(media_component->sub));
                        break;
                    }
                    sub = &media_component->sub[media_component->num_of_sub];

                    SubComponentMap = node2->data;
                    if (SubComponentMap) {
                        SubComponent = SubComponentMap->value;
                        if (SubComponent) {
                            sub->flow_number = SubComponent->f_num;
                            sub->flow_usage = SubComponent->flow_usage;

                            fDescList = SubComponent->f_descs;
                            OpenAPI_list_for_each(fDescList, node3) {
                                ogs_flow_t *flow = NULL;

                                if (sub->num_of_flow >=
                                        OGS_ARRAY_SIZE(sub->flow)) {
                                    ogs_error(
                                        "OVERFLOW sub->num_of_flow [%d:%d:%d]",
                                        sub->num_of_flow,
                                        OGS_MAX_NUM_OF_FLOW_IN_MEDIA_SUB_COMPONENT,
                                        (int)OGS_ARRAY_SIZE(sub->flow));
                                    break;
                                }
                                flow = &sub->flow[sub->num_of_flow];
                                if (node3->data) {
                                    flow->description = ogs_strdup(node3->data);
                                    ogs_assert(flow->description);

                                    sub->num_of_flow++;
                                }
                            }
                            media_component->num_of_sub++;
                        }
                    }
                }
                ims_data.num_of_media_component++;
            }
        }
    }

    rv = pcf_get_session_data(
            pcf_ue_sm->supi,
            sess->home.presence == true ? &sess->home.plmn_id : NULL,
            &sess->s_nssai, sess->dnn, &session_data, 0);
    if (rv != OGS_OK) {
        strerror = ogs_msprintf("[%s:%d] Cannot find SUPI in DB",
                pcf_ue_sm->supi, sess->psi);
        status = OGS_SBI_HTTP_STATUS_NOT_FOUND;
        goto cleanup;
    }

    memset(&SmPolicyDecision, 0, sizeof(SmPolicyDecision));

    PccRuleList = OpenAPI_list_create();
    ogs_assert(PccRuleList);

    QosDecisionList = OpenAPI_list_create();
    ogs_assert(QosDecisionList);

    for (i = 0; i < ims_data.num_of_media_component; i++) {
        int flow_presence = 0;

        ogs_pcc_rule_t *pcc_rule = NULL;
        ogs_pcc_rule_t *db_pcc_rule = NULL;
        uint8_t qos_index = 0;
        ogs_media_component_t *media_component = &ims_data.media_component[i];

        if (media_component->media_type == OpenAPI_media_type_NULL) {
            strerror = ogs_msprintf("[%s:%d] Media-Type is Required",
                    pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }

        switch(media_component->media_type) {
        case OpenAPI_media_type_AUDIO:
            qos_index = OGS_QOS_INDEX_1;
            break;
        case OpenAPI_media_type_VIDEO:
            qos_index = OGS_QOS_INDEX_2;
            break;
        case OpenAPI_media_type_CONTROL:
            qos_index = OGS_QOS_INDEX_5;
            break;
        default:
            strerror = ogs_msprintf("[%s:%d] Unknown Media-Type [%d]",
                    pcf_ue_sm->supi, sess->psi, media_component->media_type);
            status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
            goto cleanup;
        }

        for (j = 0; j < session_data.num_of_pcc_rule; j++) {
            if (session_data.pcc_rule[j].qos.index == qos_index) {
                db_pcc_rule = &session_data.pcc_rule[j];
                break;
            }
        }

        if (!db_pcc_rule &&
            (media_component->media_type == OpenAPI_media_type_CONTROL)) {
            /*
             * Check for default bearer for IMS signalling
             * QCI 5 and ARP 1
             */
            if (session_data.session.qos.index != OGS_QOS_INDEX_5 ||
                session_data.session.qos.arp.priority_level != 1) {
                strerror = ogs_msprintf("[%s:%d] CHECK WEBUI : "
                    "Even the Default Bearer(QCI:%d,ARP:%d) "
                    "cannot support IMS signalling.",
                    pcf_ue_sm->supi, sess->psi,
                    session_data.session.qos.index,
                    session_data.session.qos.arp.priority_level);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            } else {
                continue;
            }
        }

        if (!db_pcc_rule) {
            strerror = ogs_msprintf("[%s:%d] CHECK WEBUI : "
                "No PCC Rule in DB [QoS Index:%d] - "
                "Please add PCC Rule using WEBUI",
                pcf_ue_sm->supi, sess->psi, qos_index);
            status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
            goto cleanup;
        }

        for (j = 0; j < app_session->num_of_pcc_rule; j++) {
            if (app_session->pcc_rule[j].qos.index == qos_index) {
                pcc_rule = &app_session->pcc_rule[j];
                break;
            }
        }

        if (!pcc_rule) {
            pcc_rule = &app_session->pcc_rule[app_session->num_of_pcc_rule];
            ogs_assert(pcc_rule);

            pcc_rule->id = ogs_strdup(app_session->app_session_id);
            ogs_assert(pcc_rule->id);

            memcpy(&pcc_rule->qos, &db_pcc_rule->qos, sizeof(ogs_qos_t));

            pcc_rule->flow_status = db_pcc_rule->flow_status;
            pcc_rule->precedence = db_pcc_rule->precedence;

            /* Install Flow */
            flow_presence = 1;
            rv = ogs_pcc_rule_install_flow_from_media(
                    pcc_rule, media_component);
            if (rv != OGS_OK) {
                strerror = ogs_msprintf("[%s:%d] install_flow() failed",
                    pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            }

            app_session->num_of_pcc_rule++;

        } else {
            int count = 0;

            /* Check Flow */
            count = ogs_pcc_rule_num_of_flow_equal_to_media(
                    pcc_rule, media_component);
            if (count == -1) {
                strerror = ogs_msprintf("[%s:%d] matched_flow() failed",
                    pcf_ue_sm->supi, sess->psi);
                status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                goto cleanup;
            }

            if (pcc_rule->num_of_flow != count) {
                /* Re-install Flow */
                flow_presence = 1;
                rv = ogs_pcc_rule_install_flow_from_media(
                        pcc_rule, media_component);
                if (rv != OGS_OK) {
                    strerror = ogs_msprintf("[%s:%d] re-install_flow() failed",
                        pcf_ue_sm->supi, sess->psi);
                    status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
                    goto cleanup;
                }
            }
        }

        /* Update QoS */
        rv = ogs_pcc_rule_update_qos_from_media(pcc_rule, media_component);
        if (rv != OGS_OK) {
            strerror = ogs_msprintf("[%s:%d] update_qos() failed",
                pcf_ue_sm->supi, sess->psi);
            status = OGS_SBI_HTTP_STATUS_FORBIDDEN;
            goto cleanup;
        }

        /* if we failed to get QoS from IMS, apply WEBUI QoS */
        if (pcc_rule->qos.mbr.downlink == 0)
            pcc_rule->qos.mbr.downlink = db_pcc_rule->qos.mbr.downlink;
        if (pcc_rule->qos.mbr.uplink == 0)
            pcc_rule->qos.mbr.uplink = db_pcc_rule->qos.mbr.uplink;
        if (pcc_rule->qos.gbr.downlink == 0)
            pcc_rule->qos.gbr.downlink = db_pcc_rule->qos.gbr.downlink;
        if (pcc_rule->qos.gbr.uplink == 0)
            pcc_rule->qos.gbr.uplink = db_pcc_rule->qos.gbr.uplink;

        /**************************************************************
         * Build PCC Rule & QoS Decision
         *************************************************************/
        PccRule = ogs_sbi_build_pcc_rule(pcc_rule, flow_presence);
        ogs_assert(PccRule->pcc_rule_id);

        PccRuleMap = OpenAPI_map_create(PccRule->pcc_rule_id, PccRule);
        ogs_assert(PccRuleMap);

        OpenAPI_list_add(PccRuleList, PccRuleMap);

        QosData = ogs_sbi_build_qos_data(pcc_rule);
        ogs_assert(QosData);
        ogs_assert(QosData->qos_id);

        QosDecisionMap = OpenAPI_map_create(QosData->qos_id, QosData);
        ogs_assert(QosDecisionMap);

        OpenAPI_list_add(QosDecisionList, QosDecisionMap);
    }

    if (PccRuleList->count)
        SmPolicyDecision.pcc_rules = PccRuleList;

    if (QosDecisionList->count)
        SmPolicyDecision.qos_decs = QosDecisionList;

    memset(&sendmsg, 0, sizeof(sendmsg));

    sendmsg.AppSessionContextUpdateDataPatch =
        recvmsg->AppSessionContextUpdateDataPatch;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    if (PccRuleList->count || QosDecisionList->count) {
        ogs_assert(true == pcf_sbi_send_smpolicycontrol_update_notify(
                            sess, &SmPolicyDecision));
    }

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            PccRule = PccRuleMap->value;
            if (PccRule)
                ogs_sbi_free_pcc_rule(PccRule);
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    ogs_ims_data_free(&ims_data);
    OGS_SESSION_DATA_FREE(&session_data);

    return true;

cleanup:
    ogs_assert(status);
    ogs_assert(strerror);
    ogs_error("%s", strerror);
    ogs_assert(true ==
        ogs_sbi_server_send_error(stream, status, recvmsg, strerror,
                NULL, NULL));
    ogs_free(strerror);

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            PccRule = PccRuleMap->value;
            if (PccRule)
                ogs_sbi_free_pcc_rule(PccRule);
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            QosData = QosDecisionMap->value;
            if (QosData)
                ogs_sbi_free_qos_data(QosData);
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    ogs_ims_data_free(&ims_data);
    OGS_SESSION_DATA_FREE(&session_data);

    return false;
}

bool pcf_npcf_policyauthorization_handle_delete(
        pcf_sess_t *sess, pcf_app_t *app_session,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int i;

    OpenAPI_sm_policy_decision_t SmPolicyDecision;

    OpenAPI_list_t *PccRuleList = NULL;
    OpenAPI_map_t *PccRuleMap = NULL;

    OpenAPI_list_t *QosDecisionList = NULL;
    OpenAPI_map_t *QosDecisionMap = NULL;

    OpenAPI_lnode_t *node = NULL;

    ogs_assert(true == ogs_sbi_send_http_status_no_content(stream));

    ogs_assert(app_session);

    memset(&SmPolicyDecision, 0, sizeof(SmPolicyDecision));

    PccRuleList = OpenAPI_list_create();
    ogs_assert(PccRuleList);

    QosDecisionList = OpenAPI_list_create();
    ogs_assert(QosDecisionList);

    for (i = 0; i < app_session->num_of_pcc_rule; i++) {
        ogs_pcc_rule_t *pcc_rule = &app_session->pcc_rule[i];

        ogs_assert(pcc_rule);

        PccRuleMap = OpenAPI_map_create(pcc_rule->id, NULL);
        ogs_assert(PccRuleMap);

        OpenAPI_list_add(PccRuleList, PccRuleMap);

        QosDecisionMap = OpenAPI_map_create(pcc_rule->id, NULL);
        ogs_assert(QosDecisionMap);

        OpenAPI_list_add(QosDecisionList, QosDecisionMap);
    }

    if (PccRuleList->count)
        SmPolicyDecision.pcc_rules = PccRuleList;

    if (QosDecisionList->count)
        SmPolicyDecision.qos_decs = QosDecisionList;

    if (PccRuleList->count || QosDecisionList->count) {
        ogs_assert(true == pcf_sbi_send_smpolicycontrol_delete_notify(
                            sess, app_session, &SmPolicyDecision));
    } else {
        pcf_app_remove(app_session);
    }

    OpenAPI_list_for_each(PccRuleList, node) {
        PccRuleMap = node->data;
        if (PccRuleMap) {
            ogs_free(PccRuleMap);
        }
    }
    OpenAPI_list_free(PccRuleList);

    OpenAPI_list_for_each(QosDecisionList, node) {
        QosDecisionMap = node->data;
        if (QosDecisionMap) {
            ogs_free(QosDecisionMap);
        }
    }
    OpenAPI_list_free(QosDecisionList);

    return true;
}

