import { enUS } from '../locales/en-US'
import type { Locale, MessageKey, Translator } from '../messages'
import type { Issue } from './model'

// A code can describe several conditions. Match only known fixed variants and
// preserve the complete original when a payload contains unstructured details.
const fixed: Partial<Record<string, readonly MessageKey[]>> = {
  vlan_reference: ['issueVlanReference', 'issueVlanReference2'],
  gateway_address: ['issueGatewayAddress'],
  gateway_svi: ['issueGatewaySvi'],
  dhcp_bounds: ['issueDhcpBounds'],
  dhcp_gateway: ['issueDhcpGateway'],
  mac_address: ['issueMacAddress'],
  dhcp_reservation: ['issueDhcpReservation'],
  dhcp_relay_svi: ['issueDhcpRelaySvi'],
  dhcp_relay_servers: ['issueDhcpRelayServers'],
  dhcp_relay_server: ['issueDhcpRelayServer'],
  port_mode: ['issuePortMode'],
  duplicate: ['issueDuplicate', 'issueDuplicate2', 'issueDuplicate3', 'issueDuplicate4', 'issueDuplicate5', 'issueDuplicate6'],
  port_physical_only: ['issuePortPhysicalOnly'],
  port_speed_duplex: ['issuePortSpeedDuplex'],
  port_gigabit_half_unverified: ['issuePortGigabitHalfUnverified'],
  port_setting_unverified: ['issuePortSettingUnverified', 'issuePortSettingUnverified2'],
  port_layer2_only: ['issuePortLayer2Only'],
  portfast_mode: ['issuePortfastMode'],
  hardware_identity_unknown: ['issueHardwareIdentityUnknown'],
  reference: ['issueReference', 'issueReference2', 'issueReference3', 'issueReference4', 'issueReference5'],
  stack_members: ['issueStackMembers'],
  stack_chassis: ['issueStackChassis', 'issueStackChassis2'],
  stack_port: ['issueStackPort'],
  port_chassis: ['issuePortChassis'],
  port_capability_unverified: ['issuePortCapabilityUnverified'],
  svi: ['issueSvi', 'issueSvi2'],
  port_channel_interface: ['issuePortChannelInterface', 'issuePortChannelInterface2'],
  port_channel_address: ['issuePortChannelAddress'],
  empty: ['issueEmpty'],
  port_channel_member: ['issuePortChannelMember'],
  port_channel_peer_lacp: ['issuePortChannelPeerPassive', 'issuePortChannelPeerStatic'],
  topology_endpoints: ['issueTopologyEndpoints'],
  transit_core: ['issueTransitCore'],
  transit_firewall: ['issueTransitFirewall'],
  transit_management: ['issueTransitManagement'],
  transit_address: ['issueTransitAddress'],
  transit_port: ['issueTransitPort'],
  transit_link: ['issueTransitLink'],
  transit_svi: ['issueTransitSvi'],
  core_gateway: ['issueCoreGateway'],
  transit_overlap: ['issueTransitOverlap'],
  isp_port: ['issueIspPort'],
  next_hop: ['issueNextHop', 'issueNextHop2', 'issueNextHop3'],
  isp_track: ['issueIspTrack'],
  routed_public_block: ['issueRoutedPublicBlock'],
  tunnel_reference: ['issueTunnelReference', 'issueTunnelReference2'],
  tunnel_track_binding: ['issueTunnelTrackBinding'],
  vpn_prefix: ['issueVpnPrefix'],
  static_route: ['issueStaticRoute'],
  tunnel_route_track: ['issueTunnelRouteTrack'],
  route_track_reference: ['issueRouteTrackReference'],
  vpn_policy: ['issueVpnPolicy'],
  nat_exemption: ['issueNatExemption'],
  snat_reference: ['issueSnatReference'],
  isp_priority: ['issueIspPriority'],
  sbr_no_nat_reference: ['issueSbrNoNatReference'],
  sbr_isp_reference: ['issueSbrIspReference'],
  vpn_pbr_down_unverified: ['issueVpnPbrDownUnverified'],
  vpn_pbr_down_unsafe: ['issueVpnPbrDownUnsafe'],
}

export function describeIssue(issue: Issue, locale: Locale, t: Translator) {
  if (locale === 'en-US') return issue.message
  const messages = Object.hasOwn(fixed, issue.code) ? fixed[issue.code] : undefined
  const key = messages?.find((candidate) => enUS[candidate] === issue.message)
  return key ? t(key) : t('originalDiagnostic', { message: issue.message })
}
