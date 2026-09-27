/* Native experimental X2 handover for the isolated virtual LTE lab.
 * AGPL-3.0-or-later, as the surrounding srsRAN fork. */
#include "srsenb/hdr/stack/s1ap/s1ap.h"
#include "srsran/interfaces/enb_rrc_interface_s1ap.h"
#include <cstdlib>

#ifndef SRSENB_ENABLE_X2
namespace srsenb {
void s1ap::x2_tick() {}
} // namespace srsenb
#else
extern "C" {
#include "GBR-QosInformation.h"
#include "LastVisitedCell-Item.h"
#include "ProcedureCode.h"
#include "ProtocolIE-Field.h"
#include "ProtocolIE-ID.h"
#include "ProtocolIE-Single-Container.h"
#include "X2AP-PDU.h"
#include "aper_decoder.h"
#include "aper_encoder.h"
}
#include <arpa/inet.h>
#include <fcntl.h>
#include <set>
#include <stdexcept>
#include <type_traits>

namespace {
template <class T>
T* zero()
{
  auto p = static_cast<T*>(calloc(1, sizeof(T)));
  if (!p)
    throw std::bad_alloc();
  return p;
}
void octets(OCTET_STRING_t& dst, const void* data, size_t size)
{
  if (OCTET_STRING_fromBuf(&dst, static_cast<const char*>(data), size) != 0)
    throw std::bad_alloc();
}
void bits(BIT_STRING_t& dst, uint64_t value, unsigned count)
{
  dst.size        = (count + 7) / 8;
  dst.bits_unused = dst.size * 8 - count;
  dst.buf         = static_cast<uint8_t*>(calloc(dst.size, 1));
  if (!dst.buf)
    throw std::bad_alloc();
  value <<= dst.bits_unused;
  for (int i = dst.size - 1; i >= 0; --i) {
    dst.buf[i] = value & 255;
    value >>= 8;
  }
}
uint64_t number(const BIT_STRING_t& src, unsigned count)
{
  if (src.size != (count + 7) / 8 || src.bits_unused != int(src.size * 8 - count))
    throw std::runtime_error("invalid bit string");
  uint64_t value = 0;
  for (size_t i = 0; i < src.size; ++i)
    value = (value << 8) | src.buf[i];
  return value >> src.bits_unused;
}
void size_is(const OCTET_STRING_t& src, size_t size)
{
  if (src.size != size)
    throw std::runtime_error("invalid octet string");
}
// Criticality comes from the R14 schema, not from the APER encoder's type constraints.
template <class T>
long ie_criticality(long id)
{
  if (std::is_same<T, HandoverRequestAcknowledge_IEs_t>::value ||
      std::is_same<T, HandoverPreparationFailure_IEs_t>::value || std::is_same<T, E_RABs_ToBeSetup_ItemIEs_t>::value ||
      std::is_same<T, E_RABs_Admitted_ItemIEs_t>::value ||
      std::is_same<T, E_RABs_SubjectToStatusTransfer_ItemIEs_t>::value)
    return Criticality_ignore;
  if (std::is_same<T, HandoverRequest_IEs_t>::value && id == ProtocolIE_ID_id_UE_HistoryInformation)
    return Criticality_ignore;
  if (std::is_same<T, SNStatusTransfer_IEs_t>::value && id == ProtocolIE_ID_id_E_RABs_SubjectToStatusTransfer_List)
    return Criticality_ignore;
  if (std::is_same<T, HandoverCancel_IEs_t>::value && id == ProtocolIE_ID_id_New_eNB_UE_X2AP_ID)
    return Criticality_ignore;
  return Criticality_reject;
}

template <class T, class List, class PR>
T* ie(List& list, long id, PR present, long criticality = -1)
{
  auto p           = zero<T>();
  p->id            = id;
  p->criticality   = criticality < 0 ? ie_criticality<T>(id) : criticality;
  p->value.present = present;
  if (ASN_SEQUENCE_ADD(&list.list, p)) {
    free(p);
    throw std::bad_alloc();
  }
  return p;
}
template <class T, class List>
const T* find(const List& list, long id)
{
  const T* result = nullptr;
  for (int i = 0; i < list.list.count; ++i) {
    auto p = reinterpret_cast<const T*>(list.list.array[i]);
    if (p->id == id) {
      if (result)
        throw std::runtime_error("duplicate IE");
      result = p;
    }
  }
  if (!result)
    throw std::runtime_error("missing mandatory IE");
  return result;
}
struct pdu_owner {
  X2AP_PDU_t value = {};
  ~pdu_owner() { ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_X2AP_PDU, &value); }
};
void cell(ECGI_t& dst, const asn1::s1ap::eutran_cgi_s& src, uint32_t eci)
{
  octets(dst.pLMN_Identity, src.plm_nid.data(), 3);
  bits(dst.eUTRANcellIdentifier, eci, 28);
}
void tunnel(GTPtunnelEndpoint_t& dst, const asn1::bounded_bitstring<1, 160, true, true>& address, const uint8_t* teid)
{
  if (address.length() != 32)
    throw std::runtime_error("X2 lab supports IPv4 only");
  bits(dst.transportLayerAddress, address.to_number(), 32);
  octets(dst.gTP_TEID, teid, 4);
}
void qos(E_RAB_Level_QoS_Parameters_t& d, const asn1::s1ap::erab_level_qos_params_s& s)
{
  d.qCI                                                     = s.qci;
  d.allocationAndRetentionPriority.priorityLevel            = s.alloc_retention_prio.prio_level;
  d.allocationAndRetentionPriority.pre_emptionCapability    = s.alloc_retention_prio.pre_emption_cap.value;
  d.allocationAndRetentionPriority.pre_emptionVulnerability = s.alloc_retention_prio.pre_emption_vulnerability.value;
  if (s.gbr_qos_info_present) {
    d.gbrQosInformation = zero<GBR_QosInformation_t>();
    auto& q             = *d.gbrQosInformation;
    asn_ulong2INTEGER(&q.e_RAB_MaximumBitrateDL, s.gbr_qos_info.erab_maximum_bitrate_dl);
    asn_ulong2INTEGER(&q.e_RAB_MaximumBitrateUL, s.gbr_qos_info.erab_maximum_bitrate_ul);
    asn_ulong2INTEGER(&q.e_RAB_GuaranteedBitrateDL, s.gbr_qos_info.erab_guaranteed_bitrate_dl);
    asn_ulong2INTEGER(&q.e_RAB_GuaranteedBitrateUL, s.gbr_qos_info.erab_guaranteed_bitrate_ul);
  }
}
uint64_t bitrate(const INTEGER_t& src)
{
  unsigned long value = 0;
  if (asn_INTEGER2ulong(&src, &value))
    throw std::runtime_error("invalid bitrate");
  return value;
}
void qos(asn1::s1ap::erab_level_qos_params_s& d, const E_RAB_Level_QoS_Parameters_t& s)
{
  d.qci                             = s.qCI;
  d.alloc_retention_prio.prio_level = s.allocationAndRetentionPriority.priorityLevel;
  d.alloc_retention_prio.pre_emption_cap.value =
      static_cast<asn1::s1ap::pre_emption_cap_opts::options>(s.allocationAndRetentionPriority.pre_emptionCapability);
  d.alloc_retention_prio.pre_emption_vulnerability.value =
      static_cast<asn1::s1ap::pre_emption_vulnerability_opts::options>(
          s.allocationAndRetentionPriority.pre_emptionVulnerability);
  if (s.gbrQosInformation) {
    d.gbr_qos_info_present                    = true;
    const auto& q                             = *s.gbrQosInformation;
    d.gbr_qos_info.erab_maximum_bitrate_dl    = bitrate(q.e_RAB_MaximumBitrateDL);
    d.gbr_qos_info.erab_maximum_bitrate_ul    = bitrate(q.e_RAB_MaximumBitrateUL);
    d.gbr_qos_info.erab_guaranteed_bitrate_dl = bitrate(q.e_RAB_GuaranteedBitrateDL);
    d.gbr_qos_info.erab_guaranteed_bitrate_ul = bitrate(q.e_RAB_GuaranteedBitrateUL);
  }
}
} // namespace
namespace srsenb {

uint16_t s1ap::x2_allocate_id()
{
  for (unsigned attempt = 0; attempt < 4096; ++attempt) {
    uint16_t candidate = x2_next_id++ % 4096;
    bool     occupied  = std::any_of(
        x2_users.begin(), x2_users.end(), [candidate](const std::pair<const uint16_t, x2_ue_context>& entry) {
          return (entry.second.target ? entry.second.new_id : entry.second.old_id) == candidate;
        });
    if (!occupied)
      return candidate;
  }
  throw std::runtime_error("X2 ID space exhausted");
}

bool s1ap::x2_init()
{
  const char* peer = getenv("SRSRAN_LAB_X2_PEER");
  if (!peer || !*peer)
    return true;
  const char* eci    = getenv("SRSRAN_LAB_X2_PEER_ECI");
  const char* pci    = getenv("SRSRAN_LAB_X2_PCI");
  const char* earfcn = getenv("SRSRAN_LAB_X2_EARFCN");
  if (!eci || !pci || !earfcn) {
    logger.error("X2 requires explicit lab cell configuration");
    return false;
  }
  auto parse = [](const char* value, unsigned long maximum, unsigned long& output) {
    char* end = nullptr;
    errno     = 0;
    output    = strtoul(value, &end, 0);
    return !errno && end != value && !*end && output <= maximum;
  };
  unsigned long parsed_eci = 0, parsed_pci = 0, parsed_earfcn = 0;
  if (!parse(eci, 0xfffffff, parsed_eci) || !parsed_eci || !parse(pci, 503, parsed_pci) ||
      !parse(earfcn, 65535, parsed_earfcn) || parsed_earfcn != 3350) {
    logger.error("Invalid X2 lab cell settings; current profile requires EARFCN 3350");
    return false;
  }
  x2_peer_eci        = parsed_eci;
  x2_pci             = parsed_pci;
  x2_earfcn          = parsed_earfcn;
  x2_peer.sin_family = AF_INET;
  x2_peer.sin_port   = htons(36422);
  if (inet_pton(AF_INET, peer, &x2_peer.sin_addr) != 1)
    return false;
  using namespace srsran::net_utils;
  if (!x2_socket.open_socket(addr_family::ipv4, socket_type::seqpacket, protocol_type::SCTP) ||
      !x2_socket.reuse_addr() || !x2_socket.sctp_subscribe_to_events() ||
      !x2_socket.bind_addr(args.s1c_bind_addr.c_str(), 36422) || listen(x2_socket.fd(), 5) != 0)
    return false;
  x2_socket.sctp_set_init_msg_opts(2, 1000);
  int socket_flags = fcntl(x2_socket.fd(), F_GETFL, 0);
  if (socket_flags < 0 || fcntl(x2_socket.fd(), F_SETFL, socket_flags | O_NONBLOCK) < 0)
    return false;
  x2_enabled    = true;
  auto callback = [this](srsran::unique_byte_buffer_t p, const sockaddr_in& f, const sctp_sndrcvinfo& sri, int flags) {
    x2_receive(std::move(p), f, sri, flags);
  };
  rx_socket_handler->add_socket_handler(x2_socket.fd(),
                                        srsran::make_sctp_sdu_handler(logger, mme_task_queue, callback));
  logger.info("X2 lab endpoint listening on %s:36422", args.s1c_bind_addr.c_str());
  return true;
}

bool s1ap::x2_send_raw(const void* message, bool ue_message)
{
  void*   raw  = nullptr;
  ssize_t size = aper_encode_to_new_buffer(&asn_DEF_X2AP_PDU, nullptr, message, &raw);
  if (size <= 0 || size > 60000) {
    free(raw);
    logger.error("X2 APER encoding failed");
    return false;
  }
  int result = sctp_sendmsg(x2_socket.fd(),
                            raw,
                            size,
                            reinterpret_cast<sockaddr*>(&x2_peer),
                            sizeof(x2_peer),
                            htonl(27),
                            0,
                            ue_message ? 1 : 0,
                            0,
                            0);
  free(raw);
  if (result != size) {
    logger.warning("X2 SCTP send failed: %s", strerror(errno));
    return false;
  }
  return true;
}

template <class List, class IE, class PR>
void setup_ies(List&                              list,
               PR                                 global_pr,
               PR                                 cells_pr,
               PR                                 group_pr,
               const asn1::s1ap::eutran_cgi_s&    cgi,
               const asn1::s1ap::tai_s&           tai,
               uint32_t                           enbid,
               uint16_t                           pci,
               uint32_t                           earfcn,
               const asn1::s1ap::s1_setup_resp_s& response)
{
  auto& global = ie<IE>(list, ProtocolIE_ID_id_GlobalENB_ID, global_pr)->value.choice.GlobalENB_ID;
  octets(global.pLMN_Identity, cgi.plm_nid.data(), 3);
  global.eNB_ID.present = ENB_ID_PR_macro_eNB_ID;
  bits(global.eNB_ID.choice.macro_eNB_ID, enbid, 20);
  auto& cells  = ie<IE>(list, ProtocolIE_ID_id_ServedCells, cells_pr)->value.choice.ServedCells;
  auto  member = zero<ServedCells__Member>();
  ASN_SEQUENCE_ADD(&cells.list, member);
  auto& c = member->servedCellInfo;
  c.pCI   = pci;
  cell(c.cellId, cgi, cgi.cell_id.to_number());
  octets(c.tAC, tai.tac.data(), 2);
  auto plmn = zero<PLMN_Identity_t>();
  octets(*plmn, cgi.plm_nid.data(), 3);
  ASN_SEQUENCE_ADD(&c.broadcastPLMNs.list, plmn);
  c.eUTRA_Mode_Info.present     = EUTRA_Mode_Info_PR_fDD;
  auto& fdd                     = c.eUTRA_Mode_Info.choice.fDD;
  fdd.dL_EARFCN                 = earfcn;
  fdd.uL_EARFCN                 = earfcn + 18000;
  fdd.dL_Transmission_Bandwidth = Transmission_Bandwidth_bw6;
  fdd.uL_Transmission_Bandwidth = Transmission_Bandwidth_bw6;
  auto& groups                  = ie<IE>(list, ProtocolIE_ID_id_GUGroupIDList, group_pr)->value.choice.GUGroupIDList;
  if (response->served_gummeis.value.size() == 0 || response->served_gummeis.value[0].served_group_ids.size() == 0)
    throw std::runtime_error("MME has no group");
  auto group = zero<GU_Group_ID_t>();
  ASN_SEQUENCE_ADD(&groups.list, group);
  octets(group->pLMN_Identity, cgi.plm_nid.data(), 3);
  octets(group->mME_Group_ID, response->served_gummeis.value[0].served_group_ids[0].data(), 2);
}
bool s1ap::x2_setup(bool response)
{
  try {
    pdu_owner p;
    if (response) {
      p.value.present = X2AP_PDU_PR_successfulOutcome;
      auto& m         = p.value.choice.successfulOutcome;
      m.procedureCode = ProcedureCode_id_x2Setup;
      m.criticality   = Criticality_reject;
      m.value.present = SuccessfulOutcome__value_PR_X2SetupResponse;
      setup_ies<decltype(m.value.choice.X2SetupResponse.protocolIEs), X2SetupResponse_IEs_t>(
          m.value.choice.X2SetupResponse.protocolIEs,
          X2SetupResponse_IEs__value_PR_GlobalENB_ID,
          X2SetupResponse_IEs__value_PR_ServedCells,
          X2SetupResponse_IEs__value_PR_GUGroupIDList,
          eutran_cgi,
          tai,
          args.enb_id,
          x2_pci,
          x2_earfcn,
          s1setupresponse);
    } else {
      p.value.present = X2AP_PDU_PR_initiatingMessage;
      auto& m         = p.value.choice.initiatingMessage;
      m.procedureCode = ProcedureCode_id_x2Setup;
      m.criticality   = Criticality_reject;
      m.value.present = InitiatingMessage__value_PR_X2SetupRequest;
      setup_ies<decltype(m.value.choice.X2SetupRequest.protocolIEs), X2SetupRequest_IEs_t>(
          m.value.choice.X2SetupRequest.protocolIEs,
          X2SetupRequest_IEs__value_PR_GlobalENB_ID,
          X2SetupRequest_IEs__value_PR_ServedCells,
          X2SetupRequest_IEs__value_PR_GUGroupIDList,
          eutran_cgi,
          tai,
          args.enb_id,
          x2_pci,
          x2_earfcn,
          s1setupresponse);
    }
    return x2_send_raw(&p.value, false);
  } catch (const std::exception& e) {
    logger.error("X2 setup: %s", e.what());
    return false;
  }
}

void s1ap::x2_tick()
{
  ++x2_ticks;
  if (!x2_enabled)
    return;
  if (mme_connected && !x2_ready && x2_ticks >= x2_next_setup && (args.enb_id < (x2_peer_eci >> 8))) {
    x2_setup(false);
    x2_next_setup = x2_ticks + 2000;
  }
  std::vector<uint16_t> expired;
  for (const auto& pair : x2_users)
    if (pair.second.deadline <= x2_ticks)
      expired.push_back(pair.first);
  for (auto rnti : expired) {
    logger.warning("X2 handover timeout rnti=0x%x", rnti);
    x2_cancel(rnti);
  }
}

bool s1ap::x2_request(uint16_t rnti, uint32_t target_eci, srsran::unique_byte_buffer_t container)
{
  if (!mme_connected || !x2_ready || target_eci != x2_peer_eci || x2_users.count(rnti) || x2_users.size() >= 32)
    return false;
  ue* u = users.find_ue_rnti(rnti);
  if (!u || !u->ctxt.mme_ue_s1ap_id.has_value())
    return false;
  asn1::s1ap::ho_request_s context;
  if (!rrc->export_x2_context(rnti, target_eci, context))
    return false;
  if (s1setupresponse->served_gummeis.value.size() != 1)
    return false;
  const auto& gummei = s1setupresponse->served_gummeis.value[0];
  if (gummei.served_group_ids.size() != 1 || gummei.served_mmecs.size() != 1)
    return false;
  try {
    pdu_owner p;
    p.value.present = X2AP_PDU_PR_initiatingMessage;
    auto& m         = p.value.choice.initiatingMessage;
    m.procedureCode = ProcedureCode_id_handoverPreparation;
    m.criticality   = Criticality_reject;
    m.value.present = InitiatingMessage__value_PR_HandoverRequest;
    auto&    list   = m.value.choice.HandoverRequest.protocolIEs;
    uint16_t old    = x2_allocate_id();
    ie<HandoverRequest_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID, HandoverRequest_IEs__value_PR_UE_X2AP_ID)
        ->value.choice.UE_X2AP_ID = old;
    auto& cause =
        ie<HandoverRequest_IEs_t>(list, ProtocolIE_ID_id_Cause, HandoverRequest_IEs__value_PR_Cause, Criticality_ignore)
            ->value.choice.Cause;
    cause.present             = Cause_PR_radioNetwork;
    cause.choice.radioNetwork = CauseRadioNetwork_handover_desirable_for_radio_reasons;
    cell(ie<HandoverRequest_IEs_t>(list, ProtocolIE_ID_id_TargetCell_ID, HandoverRequest_IEs__value_PR_ECGI)
             ->value.choice.ECGI,
         eutran_cgi,
         target_eci);
    auto& g = ie<HandoverRequest_IEs_t>(list, ProtocolIE_ID_id_GUMMEI_ID, HandoverRequest_IEs__value_PR_GUMMEI)
                  ->value.choice.GUMMEI;
    octets(g.gU_Group_ID.pLMN_Identity, eutran_cgi.plm_nid.data(), 3);
    octets(g.gU_Group_ID.mME_Group_ID, gummei.served_group_ids[0].data(), 2);
    octets(g.mME_Code, gummei.served_mmecs[0].data(), 1);
    auto& ctx = ie<HandoverRequest_IEs_t>(
                    list, ProtocolIE_ID_id_UE_ContextInformation, HandoverRequest_IEs__value_PR_UE_ContextInformation)
                    ->value.choice.UE_ContextInformation;
    ctx.mME_UE_S1AP_ID = u->ctxt.mme_ue_s1ap_id.value();
    bits(ctx.uESecurityCapabilities.encryptionAlgorithms,
         context->ue_security_cap.value.encryption_algorithms.to_number(),
         16);
    bits(ctx.uESecurityCapabilities.integrityProtectionAlgorithms,
         context->ue_security_cap.value.integrity_protection_algorithms.to_number(),
         16);
    uint8_t key[32];
    for (unsigned i = 0; i < 32; ++i)
      key[i] = context->security_context.value.next_hop_param.data()[31 - i];
    ctx.aS_SecurityInformation.key_eNodeB_star.size = 32;
    ctx.aS_SecurityInformation.key_eNodeB_star.buf  = static_cast<uint8_t*>(malloc(32));
    memcpy(ctx.aS_SecurityInformation.key_eNodeB_star.buf, key, 32);
    ctx.aS_SecurityInformation.nextHopChainingCount = context->security_context.value.next_hop_chaining_count;
    asn_ulong2INTEGER(&ctx.uEaggregateMaximumBitRate.uEaggregateMaximumBitRateDownlink,
                      context->ueaggregate_maximum_bitrate.value.ueaggregate_maximum_bit_rate_dl);
    asn_ulong2INTEGER(&ctx.uEaggregateMaximumBitRate.uEaggregateMaximumBitRateUplink,
                      context->ueaggregate_maximum_bitrate.value.ueaggregate_maximum_bit_rate_ul);
    for (const auto& entry : context->erab_to_be_setup_list_ho_req.value) {
      const auto& b    = entry->erab_to_be_setup_item_ho_req();
      auto        item = ie<E_RABs_ToBeSetup_ItemIEs_t>(ctx.e_RABs_ToBeSetup_List,
                                                 ProtocolIE_ID_id_E_RABs_ToBeSetup_Item,
                                                 E_RABs_ToBeSetup_ItemIEs__value_PR_E_RABs_ToBeSetup_Item);
      auto&       d    = item->value.choice.E_RABs_ToBeSetup_Item;
      d.e_RAB_ID       = b.erab_id;
      qos(d.e_RAB_Level_QoS_Parameters, b.erab_level_qos_params);
      d.dL_Forwarding  = zero<DL_Forwarding_t>();
      *d.dL_Forwarding = DL_Forwarding_dL_forwardingProposed;
      tunnel(d.uL_GTPtunnelEndpoint, b.transport_layer_address, b.gtp_teid.data());
    }
    octets(ctx.rRC_Context, container->msg, container->N_bytes);
    auto& history = ie<HandoverRequest_IEs_t>(list,
                                              ProtocolIE_ID_id_UE_HistoryInformation,
                                              HandoverRequest_IEs__value_PR_UE_HistoryInformation)
                        ->value.choice.UE_HistoryInformation;
    auto visited = zero<LastVisitedCell_Item_t>();
    ASN_SEQUENCE_ADD(&history.list, visited);
    visited->present = LastVisitedCell_Item_PR_e_UTRAN_Cell;
    cell(visited->choice.e_UTRAN_Cell.global_Cell_ID, eutran_cgi, eutran_cgi.cell_id.to_number());
    visited->choice.e_UTRAN_Cell.cellType.cell_Size = Cell_Size_small;
    x2_ue_context pending;
    pending.old_id       = old;
    pending.rnti         = rnti;
    pending.deadline     = x2_ticks + 10000;
    pending.request      = context;
    pending.capabilities = context->ue_security_cap.value;
    x2_users.emplace(rnti, pending);
    if (!x2_send_raw(&p.value, true)) {
      x2_users.erase(rnti);
      return false;
    }
    logger.info("Tx X2 HandoverRequest rnti=0x%x old=%u", rnti, old);
    return true;
  } catch (const std::exception& e) {
    x2_users.erase(rnti);
    logger.error("X2 request: %s", e.what());
    return false;
  }
}

bool s1ap::x2_ack(const asn1::s1ap::ho_request_s&                msg,
                  uint16_t                                       rnti,
                  uint32_t                                       cc,
                  srsran::unique_byte_buffer_t                   command,
                  srsran::span<asn1::s1ap::erab_admitted_item_s> admitted)
{
  ue* u = users.find_ue_mmeid(msg->mme_ue_s1ap_id.value.value);
  if (!u || admitted.empty())
    return false;
  u->ctxt.rnti             = rnti;
  u->ctxt.enb_cc_idx       = cc;
  x2_incoming.rnti         = rnti;
  x2_incoming.new_id       = x2_allocate_id();
  x2_incoming.request      = msg;
  x2_incoming.capabilities = msg->ue_security_cap.value;
  x2_incoming.admitted.assign(admitted.begin(), admitted.end());
  x2_users.emplace(rnti, x2_incoming);
  pdu_owner p;
  p.value.present = X2AP_PDU_PR_successfulOutcome;
  auto& m         = p.value.choice.successfulOutcome;
  m.procedureCode = ProcedureCode_id_handoverPreparation;
  m.criticality   = Criticality_reject;
  m.value.present = SuccessfulOutcome__value_PR_HandoverRequestAcknowledge;
  auto& list      = m.value.choice.HandoverRequestAcknowledge.protocolIEs;
  ie<HandoverRequestAcknowledge_IEs_t>(
      list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID, HandoverRequestAcknowledge_IEs__value_PR_UE_X2AP_ID)
      ->value.choice.UE_X2AP_ID = x2_incoming.old_id;
  ie<HandoverRequestAcknowledge_IEs_t>(
      list, ProtocolIE_ID_id_New_eNB_UE_X2AP_ID, HandoverRequestAcknowledge_IEs__value_PR_UE_X2AP_ID_1)
      ->value.choice.UE_X2AP_ID_1 = x2_incoming.new_id;
  auto& bears                     = ie<HandoverRequestAcknowledge_IEs_t>(list,
                                                     ProtocolIE_ID_id_E_RABs_Admitted_List,
                                                     HandoverRequestAcknowledge_IEs__value_PR_E_RABs_Admitted_List)
                    ->value.choice.E_RABs_Admitted_List;
  for (const auto& b : admitted) {
    auto item = ie<E_RABs_Admitted_ItemIEs_t>(
        bears, ProtocolIE_ID_id_E_RABs_Admitted_Item, E_RABs_Admitted_ItemIEs__value_PR_E_RABs_Admitted_Item);
    auto& d    = item->value.choice.E_RABs_Admitted_Item;
    d.e_RAB_ID = b.erab_id;
    if (b.dl_g_tp_teid_present) {
      d.dL_GTP_TunnelEndpoint = zero<GTPtunnelEndpoint_t>();
      in_addr ip{};
      inet_pton(AF_INET, args.gtp_bind_addr.c_str(), &ip);
      asn1::bounded_bitstring<1, 160, true, true> addr;
      addr.from_number(ntohl(ip.s_addr), 32);
      tunnel(*d.dL_GTP_TunnelEndpoint, addr, b.dl_g_tp_teid.data());
    }
  }
  auto& rrc_cmd = ie<HandoverRequestAcknowledge_IEs_t>(
                      list,
                      ProtocolIE_ID_id_TargeteNBtoSource_eNBTransparentContainer,
                      HandoverRequestAcknowledge_IEs__value_PR_TargeteNBtoSource_eNBTransparentContainer)
                      ->value.choice.TargeteNBtoSource_eNBTransparentContainer;
  octets(rrc_cmd, command->msg, command->N_bytes);
  logger.info("Tx X2 HandoverRequestAcknowledge rnti=0x%x old=%u new=%u", rnti, x2_incoming.old_id, x2_incoming.new_id);
  return x2_send_raw(&p.value, true);
}

bool s1ap::x2_status(uint16_t rnti, const std::vector<bearer_status_info>& status)
{
  auto it = x2_users.find(rnti);
  if (it == x2_users.end() || it->second.target)
    return false;
  auto&     ctx = it->second;
  pdu_owner p;
  p.value.present = X2AP_PDU_PR_initiatingMessage;
  auto& m         = p.value.choice.initiatingMessage;
  m.procedureCode = ProcedureCode_id_snStatusTransfer;
  m.criticality   = Criticality_ignore;
  m.value.present = InitiatingMessage__value_PR_SNStatusTransfer;
  auto& list      = m.value.choice.SNStatusTransfer.protocolIEs;
  ie<SNStatusTransfer_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID, SNStatusTransfer_IEs__value_PR_UE_X2AP_ID)
      ->value.choice.UE_X2AP_ID = ctx.old_id;
  ie<SNStatusTransfer_IEs_t>(list, ProtocolIE_ID_id_New_eNB_UE_X2AP_ID, SNStatusTransfer_IEs__value_PR_UE_X2AP_ID_1)
      ->value.choice.UE_X2AP_ID_1 = ctx.new_id;
  auto& bears                     = ie<SNStatusTransfer_IEs_t>(list,
                                           ProtocolIE_ID_id_E_RABs_SubjectToStatusTransfer_List,
                                           SNStatusTransfer_IEs__value_PR_E_RABs_SubjectToStatusTransfer_List)
                    ->value.choice.E_RABs_SubjectToStatusTransfer_List;
  for (const auto& b : status) {
    auto item = ie<E_RABs_SubjectToStatusTransfer_ItemIEs_t>(
        bears,
        ProtocolIE_ID_id_E_RABs_SubjectToStatusTransfer_Item,
        E_RABs_SubjectToStatusTransfer_ItemIEs__value_PR_E_RABs_SubjectToStatusTransfer_Item);
    auto& d                 = item->value.choice.E_RABs_SubjectToStatusTransfer_Item;
    d.e_RAB_ID              = b.erab_id;
    d.dL_COUNTvalue.pDCP_SN = b.pdcp_dl_sn;
    d.dL_COUNTvalue.hFN     = b.dl_hfn;
    d.uL_COUNTvalue.pDCP_SN = b.pdcp_ul_sn;
    d.uL_COUNTvalue.hFN     = b.ul_hfn;
  }
  logger.info("Tx X2 SNStatusTransfer rnti=0x%x", rnti);
  return x2_send_raw(&p.value, true);
}

bool s1ap::x2_release(uint16_t rnti)
{
  auto it = x2_users.find(rnti);
  if (it == x2_users.end() || !it->second.target)
    return false;
  pdu_owner p;
  p.value.present = X2AP_PDU_PR_initiatingMessage;
  auto& m         = p.value.choice.initiatingMessage;
  m.procedureCode = ProcedureCode_id_uEContextRelease;
  m.criticality   = Criticality_ignore;
  m.value.present = InitiatingMessage__value_PR_UEContextRelease;
  auto& list      = m.value.choice.UEContextRelease.protocolIEs;
  ie<UEContextRelease_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID, UEContextRelease_IEs__value_PR_UE_X2AP_ID)
      ->value.choice.UE_X2AP_ID = it->second.old_id;
  ie<UEContextRelease_IEs_t>(list, ProtocolIE_ID_id_New_eNB_UE_X2AP_ID, UEContextRelease_IEs__value_PR_UE_X2AP_ID_1)
      ->value.choice.UE_X2AP_ID_1 = it->second.new_id;
  bool sent                       = x2_send_raw(&p.value, true);
  if (sent)
    x2_users.erase(it);
  return sent;
}
void s1ap::x2_failure(uint16_t old)
{
  pdu_owner p;
  p.value.present = X2AP_PDU_PR_unsuccessfulOutcome;
  auto& m         = p.value.choice.unsuccessfulOutcome;
  m.procedureCode = ProcedureCode_id_handoverPreparation;
  m.criticality   = Criticality_reject;
  m.value.present = UnsuccessfulOutcome__value_PR_HandoverPreparationFailure;
  auto& list      = m.value.choice.HandoverPreparationFailure.protocolIEs;
  ie<HandoverPreparationFailure_IEs_t>(
      list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID, HandoverPreparationFailure_IEs__value_PR_UE_X2AP_ID)
      ->value.choice.UE_X2AP_ID = old;
  auto& cause                   = ie<HandoverPreparationFailure_IEs_t>(
                    list, ProtocolIE_ID_id_Cause, HandoverPreparationFailure_IEs__value_PR_Cause, Criticality_ignore)
                    ->value.choice.Cause;
  cause.present             = Cause_PR_radioNetwork;
  cause.choice.radioNetwork = CauseRadioNetwork_no_radio_resources_available_in_target_cell;
  x2_send_raw(&p.value, true);
}
void s1ap::x2_cancel(uint16_t rnti)
{
  auto it = x2_users.find(rnti);
  if (it == x2_users.end())
    return;
  auto ctx = it->second;
  x2_users.erase(it);
  if (ctx.target) {
    rrc->release_erabs(rnti);
    rrc->release_ue(rnti);
    auto u = users.find_ue_rnti(rnti);
    if (u)
      users.erase(u);
    return;
  }
  pdu_owner p;
  p.value.present = X2AP_PDU_PR_initiatingMessage;
  auto& m         = p.value.choice.initiatingMessage;
  m.procedureCode = ProcedureCode_id_handoverCancel;
  m.criticality   = Criticality_ignore;
  m.value.present = InitiatingMessage__value_PR_HandoverCancel;
  auto& list      = m.value.choice.HandoverCancel.protocolIEs;
  ie<HandoverCancel_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID, HandoverCancel_IEs__value_PR_UE_X2AP_ID)
      ->value.choice.UE_X2AP_ID = ctx.old_id;
  if (ctx.command_sent)
    ie<HandoverCancel_IEs_t>(list, ProtocolIE_ID_id_New_eNB_UE_X2AP_ID, HandoverCancel_IEs__value_PR_UE_X2AP_ID_1)
        ->value.choice.UE_X2AP_ID_1 = ctx.new_id;
  auto& cause =
      ie<HandoverCancel_IEs_t>(list, ProtocolIE_ID_id_Cause, HandoverCancel_IEs__value_PR_Cause, Criticality_ignore)
          ->value.choice.Cause;
  cause.present             = Cause_PR_radioNetwork;
  cause.choice.radioNetwork = CauseRadioNetwork_unspecified;
  x2_send_raw(&p.value, true);
  if (!ctx.command_sent)
    rrc->ho_preparation_complete(rnti, rrc_interface_s1ap::ho_prep_result::timeout, {}, nullptr);
  else {
    rrc->release_erabs(rnti);
    rrc->release_ue(rnti);
    auto u = users.find_ue_rnti(rnti);
    if (u)
      users.erase(u);
  }
}

bool s1ap::x2_path_switch(uint16_t rnti, uint64_t eci)
{
  auto it = x2_users.find(rnti);
  auto u  = users.find_ue_rnti(rnti);
  if (it == x2_users.end() || !it->second.target || !u)
    return false;
  asn1::s1ap::s1ap_pdu_c p;
  p.set_init_msg().load_info_obj(ASN1_S1AP_ID_PATH_SWITCH_REQUEST);
  auto& m                        = p.init_msg().value.path_switch_request();
  m->enb_ue_s1ap_id.value        = u->ctxt.enb_ue_s1ap_id;
  m->source_mme_ue_s1ap_id.value = u->ctxt.mme_ue_s1ap_id.value();
  m->tai.value                   = tai;
  m->eutran_cgi.value            = eutran_cgi;
  m->eutran_cgi.value.cell_id.from_number(eci);
  m->ue_security_cap.value = it->second.capabilities;
  auto& list               = m->erab_to_be_switched_dl_list.value;
  list.resize(it->second.admitted.size());
  for (unsigned i = 0; i < list.size(); ++i) {
    list[i].load_info_obj(ASN1_S1AP_ID_ERAB_TO_BE_SWITCHED_DL_ITEM);
    auto& b    = list[i]->erab_to_be_switched_dl_item();
    b.erab_id  = it->second.admitted[i].erab_id;
    b.gtp_teid = it->second.admitted[i].gtp_teid;
    in_addr ip{};
    inet_pton(AF_INET, args.gtp_bind_addr.c_str(), &ip);
    b.transport_layer_address.from_number(ntohl(ip.s_addr), 32);
  }
  return sctp_send_s1ap_pdu(p, rnti, "X2PathSwitchRequest");
}
bool s1ap::x2_path_ack(const asn1::s1ap::path_switch_request_ack_s& msg)
{
  auto u = users.find_ue_enbid(msg->enb_ue_s1ap_id.value.value);
  if (!u || !x2_users.count(u->ctxt.rnti) || !x2_users.at(u->ctxt.rnti).target)
    return false;
  if (msg->erab_to_be_released_list_present && msg->erab_to_be_released_list.value.size() != 0) {
    x2_cancel(u->ctxt.rnti);
    return false;
  }
  // The first lab supports a stationary SGW. Reject relocation until tunnel update is implemented.
  if (msg->erab_to_be_switched_ul_list_present) {
    const auto& original = x2_users.at(u->ctxt.rnti).request->erab_to_be_setup_list_ho_req.value;
    for (const auto& entry : msg->erab_to_be_switched_ul_list.value) {
      const auto& switched = entry->erab_to_be_switched_ul_item();
      auto        found    = std::find_if(
          original.begin(),
          original.end(),
          [&switched](const asn1::protocol_ie_single_container_s<asn1::s1ap::erab_to_be_setup_item_ho_req_ies_o>& v) {
            return v->erab_to_be_setup_item_ho_req().erab_id == switched.erab_id;
          });
      if (found == original.end() ||
          memcmp((*found)->erab_to_be_setup_item_ho_req().gtp_teid.data(), switched.gtp_teid.data(), 4) != 0 ||
          !((*found)->erab_to_be_setup_item_ho_req().transport_layer_address == switched.transport_layer_address)) {
        logger.error("X2 SGW relocation unsupported");
        x2_cancel(u->ctxt.rnti);
        return false;
      }
    }
  }
  u->ctxt.mme_ue_s1ap_id = msg->mme_ue_s1ap_id.value.value;
  rrc->update_x2_security(u->ctxt.rnti, msg->security_context.value);
  logger.info("X2 PathSwitch acknowledged rnti=0x%x", u->ctxt.rnti);
  return x2_release(u->ctxt.rnti);
}

template <class List, class IE>
bool valid_setup(const List& list, uint32_t eci, const asn1::s1ap::eutran_cgi_s& cgi)
{
  const auto& global = find<IE>(list, ProtocolIE_ID_id_GlobalENB_ID)->value.choice.GlobalENB_ID;
  size_is(global.pLMN_Identity, 3);
  if (memcmp(global.pLMN_Identity.buf, cgi.plm_nid.data(), 3) || global.eNB_ID.present != ENB_ID_PR_macro_eNB_ID ||
      number(global.eNB_ID.choice.macro_eNB_ID, 20) != (eci >> 8))
    return false;
  const auto& served = find<IE>(list, ProtocolIE_ID_id_ServedCells)->value.choice.ServedCells;
  if (served.list.count != 1)
    return false;
  return number(served.list.array[0]->servedCellInfo.cellId.eUTRANcellIdentifier, 28) == eci;
}
void s1ap::x2_receive(srsran::unique_byte_buffer_t pdu, const sockaddr_in& from, const sctp_sndrcvinfo& sri, int flags)
{
  if (flags & MSG_NOTIFICATION) {
    auto n = reinterpret_cast<const union sctp_notification*>(pdu->msg);
    if (pdu->N_bytes >= sizeof(n->sn_header) &&
        (n->sn_header.sn_type == SCTP_SHUTDOWN_EVENT ||
         (n->sn_header.sn_type == SCTP_ASSOC_CHANGE && pdu->N_bytes >= sizeof(n->sn_assoc_change) &&
          (n->sn_assoc_change.sac_state == SCTP_COMM_LOST || n->sn_assoc_change.sac_state == SCTP_SHUTDOWN_COMP)))) {
      x2_ready = false;
      std::vector<uint16_t> active;
      for (const auto& pair : x2_users)
        active.push_back(pair.first);
      for (auto rnti : active)
        x2_cancel(rnti);
    }
    return;
  }
  if (from.sin_addr.s_addr != x2_peer.sin_addr.s_addr || ntohl(sri.sinfo_ppid) != 27 || !pdu->N_bytes)
    return;
  X2AP_PDU_t* decoded = nullptr;
  auto        result =
      aper_decode_complete(nullptr, &asn_DEF_X2AP_PDU, reinterpret_cast<void**>(&decoded), pdu->msg, pdu->N_bytes);
  if (result.code != RC_OK || result.consumed != pdu->N_bytes) {
    if (decoded)
      ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, decoded);
    logger.error("Malformed X2 PDU");
    return;
  }
  std::unique_ptr<X2AP_PDU_t, void (*)(X2AP_PDU_t*)> owner(decoded,
                                                           [](X2AP_PDU_t* p) { ASN_STRUCT_FREE(asn_DEF_X2AP_PDU, p); });
  try {
    if (decoded->present == X2AP_PDU_PR_initiatingMessage) {
      const auto& m = decoded->choice.initiatingMessage;
      switch (m.value.present) {
        case InitiatingMessage__value_PR_X2SetupRequest:
          if (mme_connected && valid_setup<decltype(m.value.choice.X2SetupRequest.protocolIEs), X2SetupRequest_IEs_t>(
                                   m.value.choice.X2SetupRequest.protocolIEs, x2_peer_eci, eutran_cgi)) {
            x2_ready = x2_setup(true);
            logger.info("X2 Setup request accepted ready=%d", x2_ready);
          }
          break;
        case InitiatingMessage__value_PR_HandoverRequest: {
          if (!x2_ready || !mme_connected || x2_users.size() >= 32)
            break;
          const auto& list = m.value.choice.HandoverRequest.protocolIEs;
          uint16_t    old =
              find<HandoverRequest_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID)->value.choice.UE_X2AP_ID;
          const auto& target = find<HandoverRequest_IEs_t>(list, ProtocolIE_ID_id_TargetCell_ID)->value.choice.ECGI;
          if (number(target.eUTRANcellIdentifier, 28) != eutran_cgi.cell_id.to_number()) {
            x2_failure(old);
            break;
          }
          const auto& g = find<HandoverRequest_IEs_t>(list, ProtocolIE_ID_id_GUMMEI_ID)->value.choice.GUMMEI;
          size_is(g.gU_Group_ID.pLMN_Identity, 3);
          size_is(g.gU_Group_ID.mME_Group_ID, 2);
          size_is(g.mME_Code, 1);
          const auto& served = s1setupresponse->served_gummeis.value;
          if (served.size() != 1 || served[0].served_group_ids.size() != 1 || served[0].served_mmecs.size() != 1 ||
              memcmp(g.gU_Group_ID.pLMN_Identity.buf, eutran_cgi.plm_nid.data(), 3) ||
              memcmp(g.gU_Group_ID.mME_Group_ID.buf, served[0].served_group_ids[0].data(), 2) ||
              memcmp(g.mME_Code.buf, served[0].served_mmecs[0].data(), 1)) {
            x2_failure(old);
            break;
          }
          const auto& ctx = find<HandoverRequest_IEs_t>(list, ProtocolIE_ID_id_UE_ContextInformation)
                                ->value.choice.UE_ContextInformation;
          if (users.find_ue_mmeid(ctx.mME_UE_S1AP_ID)) {
            x2_failure(old);
            break;
          }
          asn1::s1ap::ho_request_s request;
          request->mme_ue_s1ap_id.value = ctx.mME_UE_S1AP_ID;
          request->handov_type.value    = asn1::s1ap::handov_type_opts::intralte;
          request->cause.value.set_radio_network().value =
              asn1::s1ap::cause_radio_network_opts::ho_desirable_for_radio_reason;
          auto& caps = request->ue_security_cap.value;
          caps.encryption_algorithms.from_number(number(ctx.uESecurityCapabilities.encryptionAlgorithms, 16));
          caps.integrity_protection_algorithms.from_number(
              number(ctx.uESecurityCapabilities.integrityProtectionAlgorithms, 16));
          const auto& key = ctx.aS_SecurityInformation.key_eNodeB_star;
          if (key.size != 32 || key.bits_unused)
            throw std::runtime_error("invalid KeNB*");
          for (unsigned i = 0; i < 32; ++i)
            request->security_context.value.next_hop_param.data()[i] = key.buf[31 - i];
          request->security_context.value.next_hop_chaining_count = ctx.aS_SecurityInformation.nextHopChainingCount;
          request->ueaggregate_maximum_bitrate.value.ueaggregate_maximum_bit_rate_dl =
              bitrate(ctx.uEaggregateMaximumBitRate.uEaggregateMaximumBitRateDownlink);
          request->ueaggregate_maximum_bitrate.value.ueaggregate_maximum_bit_rate_ul =
              bitrate(ctx.uEaggregateMaximumBitRate.uEaggregateMaximumBitRateUplink);
          auto& bears = request->erab_to_be_setup_list_ho_req.value;
          if (ctx.e_RABs_ToBeSetup_List.list.count < 1 || ctx.e_RABs_ToBeSetup_List.list.count > 16)
            throw std::runtime_error("invalid bearer count");
          bears.resize(ctx.e_RABs_ToBeSetup_List.list.count);
          asn1::s1ap::sourceenb_to_targetenb_transparent_container_s container;
          container.target_cell_id = eutran_cgi;
          container.rrc_container.resize(ctx.rRC_Context.size);
          if (ctx.rRC_Context.size > 8192)
            throw std::runtime_error("oversized RRC context");
          memcpy(container.rrc_container.data(), ctx.rRC_Context.buf, ctx.rRC_Context.size);
          container.erab_info_list_present = true;
          container.erab_info_list.resize(bears.size());
          std::set<unsigned> ids;
          for (unsigned i = 0; i < bears.size(); ++i) {
            auto item = reinterpret_cast<const E_RABs_ToBeSetup_ItemIEs_t*>(ctx.e_RABs_ToBeSetup_List.list.array[i]);
            if (item->id != ProtocolIE_ID_id_E_RABs_ToBeSetup_Item ||
                item->value.present != E_RABs_ToBeSetup_ItemIEs__value_PR_E_RABs_ToBeSetup_Item)
              throw std::runtime_error("invalid bearer IE");
            const auto& b = item->value.choice.E_RABs_ToBeSetup_Item;
            if (!ids.insert(b.e_RAB_ID).second)
              throw std::runtime_error("duplicate bearer");
            bears[i].load_info_obj(ASN1_S1AP_ID_ERAB_TO_BE_SETUP_ITEM_HO_REQ);
            auto& d   = bears[i]->erab_to_be_setup_item_ho_req();
            d.erab_id = b.e_RAB_ID;
            qos(d.erab_level_qos_params, b.e_RAB_Level_QoS_Parameters);
            d.transport_layer_address.from_number(number(b.uL_GTPtunnelEndpoint.transportLayerAddress, 32), 32);
            size_is(b.uL_GTPtunnelEndpoint.gTP_TEID, 4);
            memcpy(d.gtp_teid.data(), b.uL_GTPtunnelEndpoint.gTP_TEID.buf, 4);
            container.erab_info_list[i].load_info_obj(ASN1_S1AP_ID_ERAB_INFO_LIST_ITEM);
            auto& f   = container.erab_info_list[i]->erab_info_list_item();
            f.erab_id = b.e_RAB_ID;
            if (b.dL_Forwarding) {
              f.dl_forwarding_present = true;
              f.dl_forwarding.value   = asn1::s1ap::dl_forwarding_opts::dl_forwarding_proposed;
            }
          }
          std::unique_ptr<ue> u(new ue(this));
          u->ctxt.mme_ue_s1ap_id = ctx.mME_UE_S1AP_ID;
          if (!users.add_user(std::move(u))) {
            x2_failure(old);
            break;
          }
          x2_incoming          = {};
          x2_incoming.old_id   = old;
          x2_incoming.target   = true;
          x2_incoming.deadline = x2_ticks + 10000;
          x2_target_allocating = true;
          asn1::s1ap::cause_c cause;
          uint16_t            rnti = rrc->start_ho_ue_resource_alloc(request, container, cause);
          x2_target_allocating     = false;
          if (rnti == SRSRAN_INVALID_RNTI) {
            for (auto it = x2_users.begin(); it != x2_users.end();) {
              if (it->second.target && it->second.old_id == old)
                it = x2_users.erase(it);
              else
                ++it;
            }
            auto user = users.find_ue_mmeid(ctx.mME_UE_S1AP_ID);
            if (user)
              users.erase(user);
            x2_failure(old);
          } else
            logger.info("Rx X2 HandoverRequest allocated rnti=0x%x old=%u", rnti, old);
          break;
        }
        case InitiatingMessage__value_PR_SNStatusTransfer: {
          const auto& list = m.value.choice.SNStatusTransfer.protocolIEs;
          uint16_t    old =
              find<SNStatusTransfer_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID)->value.choice.UE_X2AP_ID;
          uint16_t next =
              find<SNStatusTransfer_IEs_t>(list, ProtocolIE_ID_id_New_eNB_UE_X2AP_ID)->value.choice.UE_X2AP_ID_1;
          auto it = std::find_if(
              x2_users.begin(), x2_users.end(), [old, next](const std::pair<const uint16_t, x2_ue_context>& p) {
                return p.second.target && p.second.old_id == old && p.second.new_id == next;
              });
          if (it == x2_users.end())
            break;
          const auto& bears = find<SNStatusTransfer_IEs_t>(list, ProtocolIE_ID_id_E_RABs_SubjectToStatusTransfer_List)
                                  ->value.choice.E_RABs_SubjectToStatusTransfer_List;
          asn1::s1ap::bearers_subject_to_status_transfer_list_l transfer;
          transfer.resize(bears.list.count);
          for (int i = 0; i < bears.list.count; ++i) {
            auto        item = reinterpret_cast<const E_RABs_SubjectToStatusTransfer_ItemIEs_t*>(bears.list.array[i]);
            const auto& b    = item->value.choice.E_RABs_SubjectToStatusTransfer_Item;
            transfer[i].load_info_obj(ASN1_S1AP_ID_BEARERS_SUBJECT_TO_STATUS_TRANSFER_ITEM);
            auto& d                  = transfer[i]->bearers_subject_to_status_transfer_item();
            d.erab_id                = b.e_RAB_ID;
            d.dl_coun_tvalue.pdcp_sn = b.dL_COUNTvalue.pDCP_SN;
            d.dl_coun_tvalue.hfn     = b.dL_COUNTvalue.hFN;
            d.ul_coun_tvalue.pdcp_sn = b.uL_COUNTvalue.pDCP_SN;
            d.ul_coun_tvalue.hfn     = b.uL_COUNTvalue.hFN;
          }
          rrc->set_erab_status(it->first, transfer);
          logger.info("Rx X2 SNStatusTransfer rnti=0x%x", it->first);
          break;
        }
        case InitiatingMessage__value_PR_UEContextRelease: {
          const auto& list = m.value.choice.UEContextRelease.protocolIEs;
          uint16_t    old =
              find<UEContextRelease_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID)->value.choice.UE_X2AP_ID;
          uint16_t next =
              find<UEContextRelease_IEs_t>(list, ProtocolIE_ID_id_New_eNB_UE_X2AP_ID)->value.choice.UE_X2AP_ID_1;
          auto it = std::find_if(
              x2_users.begin(), x2_users.end(), [old, next](const std::pair<const uint16_t, x2_ue_context>& p) {
                return !p.second.target && p.second.command_sent && p.second.old_id == old && p.second.new_id == next;
              });
          if (it != x2_users.end()) {
            uint16_t rnti = it->first;
            x2_users.erase(it);
            rrc->release_erabs(rnti);
            rrc->release_ue(rnti);
            auto u = users.find_ue_rnti(rnti);
            if (u)
              users.erase(u);
            logger.info("Rx X2 UEContextRelease cleaned source rnti=0x%x", rnti);
          }
          break;
        }
        case InitiatingMessage__value_PR_HandoverCancel: {
          const auto& list = m.value.choice.HandoverCancel.protocolIEs;
          uint16_t old = find<HandoverCancel_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID)->value.choice.UE_X2AP_ID;
          auto     it =
              std::find_if(x2_users.begin(), x2_users.end(), [old](const std::pair<const uint16_t, x2_ue_context>& p) {
                return p.second.target && p.second.old_id == old;
              });
          if (it != x2_users.end())
            x2_cancel(it->first);
          break;
        }
        default:
          logger.warning("Unsupported X2 initiating procedure %ld", m.procedureCode);
      }
    } else if (decoded->present == X2AP_PDU_PR_successfulOutcome) {
      const auto& m = decoded->choice.successfulOutcome;
      if (m.value.present == SuccessfulOutcome__value_PR_X2SetupResponse) {
        x2_ready = valid_setup<decltype(m.value.choice.X2SetupResponse.protocolIEs), X2SetupResponse_IEs_t>(
            m.value.choice.X2SetupResponse.protocolIEs, x2_peer_eci, eutran_cgi);
        logger.info("X2 Setup response ready=%d", x2_ready);
      } else if (m.value.present == SuccessfulOutcome__value_PR_HandoverRequestAcknowledge) {
        const auto& list = m.value.choice.HandoverRequestAcknowledge.protocolIEs;
        uint16_t    old =
            find<HandoverRequestAcknowledge_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID)->value.choice.UE_X2AP_ID;
        auto it =
            std::find_if(x2_users.begin(), x2_users.end(), [old](const std::pair<const uint16_t, x2_ue_context>& p) {
              return !p.second.target && !p.second.command_sent && p.second.old_id == old;
            });
        if (it == x2_users.end())
          return;
        it->second.new_id = find<HandoverRequestAcknowledge_IEs_t>(list, ProtocolIE_ID_id_New_eNB_UE_X2AP_ID)
                                ->value.choice.UE_X2AP_ID_1;
        const auto& cmd =
            find<HandoverRequestAcknowledge_IEs_t>(list, ProtocolIE_ID_id_TargeteNBtoSource_eNBTransparentContainer)
                ->value.choice.TargeteNBtoSource_eNBTransparentContainer;
        if (cmd.size > 8192)
          throw std::runtime_error("oversized HO command");
        auto rrc_command = srsran::make_byte_buffer();
        if (!rrc_command)
          throw std::bad_alloc();
        memcpy(rrc_command->msg, cmd.buf, cmd.size);
        rrc_command->N_bytes = cmd.size;
        asn1::s1ap::ho_cmd_s command;
        const auto&          bears = find<HandoverRequestAcknowledge_IEs_t>(list, ProtocolIE_ID_id_E_RABs_Admitted_List)
                                ->value.choice.E_RABs_Admitted_List;
        const auto& requested = it->second.request->erab_to_be_setup_list_ho_req.value;
        if (bears.list.count != int(requested.size())) {
          const uint16_t rejected_rnti = it->first;
          x2_cancel(rejected_rnti);
          return;
        }
        std::set<unsigned> admitted_ids;
        for (int index = 0; index < bears.list.count; ++index) {
          const auto* admitted = reinterpret_cast<const E_RABs_Admitted_ItemIEs_t*>(bears.list.array[index]);
          unsigned    id       = admitted->value.choice.E_RABs_Admitted_Item.e_RAB_ID;
          auto        match    = std::find_if(
              requested.begin(),
              requested.end(),
              [id](const asn1::protocol_ie_single_container_s<asn1::s1ap::erab_to_be_setup_item_ho_req_ies_o>& item) {
                return item->erab_to_be_setup_item_ho_req().erab_id == id;
              });
          if (match == requested.end() || !admitted_ids.insert(id).second) {
            const uint16_t rejected_rnti = it->first;
            x2_cancel(rejected_rnti);
            return;
          }
        }
        command->erab_subjectto_data_forwarding_list_present = true;
        auto& forward                                        = command->erab_subjectto_data_forwarding_list.value;
        forward.resize(bears.list.count);
        for (int i = 0; i < bears.list.count; ++i) {
          auto        item = reinterpret_cast<const E_RABs_Admitted_ItemIEs_t*>(bears.list.array[i]);
          const auto& b    = item->value.choice.E_RABs_Admitted_Item;
          forward[i].load_info_obj(ASN1_S1AP_ID_ERAB_DATA_FORWARDING_ITEM);
          auto& d   = forward[i]->erab_data_forwarding_item();
          d.erab_id = b.e_RAB_ID;
          if (b.dL_GTP_TunnelEndpoint) {
            d.dl_g_tp_teid_present               = true;
            d.dl_transport_layer_address_present = true;
            d.dl_transport_layer_address.from_number(number(b.dL_GTP_TunnelEndpoint->transportLayerAddress, 32), 32);
            size_is(b.dL_GTP_TunnelEndpoint->gTP_TEID, 4);
            memcpy(d.dl_g_tp_teid.data(), b.dL_GTP_TunnelEndpoint->gTP_TEID.buf, 4);
          }
        }
        it->second.command_sent    = true;
        const uint16_t source_rnti = it->first;
        rrc->ho_preparation_complete(
            source_rnti, rrc_interface_s1ap::ho_prep_result::success, command, std::move(rrc_command));
        logger.info("Rx X2 HandoverRequestAcknowledge source rnti=0x%x", source_rnti);
      }
    } else if (decoded->present == X2AP_PDU_PR_unsuccessfulOutcome &&
               decoded->choice.unsuccessfulOutcome.value.present ==
                   UnsuccessfulOutcome__value_PR_HandoverPreparationFailure) {
      const auto& list = decoded->choice.unsuccessfulOutcome.value.choice.HandoverPreparationFailure.protocolIEs;
      uint16_t    old =
          find<HandoverPreparationFailure_IEs_t>(list, ProtocolIE_ID_id_Old_eNB_UE_X2AP_ID)->value.choice.UE_X2AP_ID;
      auto it =
          std::find_if(x2_users.begin(), x2_users.end(), [old](const std::pair<const uint16_t, x2_ue_context>& p) {
            return !p.second.target && p.second.old_id == old;
          });
      if (it != x2_users.end()) {
        uint16_t rnti = it->first;
        x2_users.erase(it);
        rrc->ho_preparation_complete(rnti, rrc_interface_s1ap::ho_prep_result::failure, {}, nullptr);
      }
    }
  } catch (const std::exception& e) {
    x2_target_allocating = false;
    logger.error("Rejected X2 message: %s", e.what());
  }
}
} // namespace srsenb
#endif
