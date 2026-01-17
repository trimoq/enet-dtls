use std::fmt::Display;

use bytes::{Buf, BufMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnetParseError {
    #[error("unexpected end of buffer: need {needed} bytes, have {available}")]
    UnexpectedEof { needed: usize, available: usize },
    #[error("unknown command type: {0}")]
    UnknownCommand(u8),
}

/// ENet Protocol Header
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetProtocolHeader {
    pub peer_id: u16,
    pub sent_time: Option<u16>,
}

/// ENet Command Header (common to all commands)
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetCommandHeader {
    pub command: u8,
    pub channel_id: u8,
    pub reliable_seq_num: u16,
}

/// ENet Acknowledge Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetAcknowledge {
    pub received_reliable_seq_num: u16,
    pub received_sent_time: u16,
}

/// ENet Connect Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetConnect {
    pub outgoing_peer_id: u16,
    pub incoming_session_id: u8,
    pub outgoing_session_id: u8,
    pub mtu: u32,
    pub window_size: u32,
    pub channel_count: u32,
    pub incoming_bandwidth: u32,
    pub outgoing_bandwidth: u32,
    pub packet_throttle_interval: u32,
    pub packet_throttle_accel: u32,
    pub packet_throttle_decel: u32,
    pub connect_id: u32,
    pub data: u32,
}

/// ENet Verify Connect Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetVerifyConnect {
    pub outgoing_peer_id: u16,
    pub incoming_session_id: u8,
    pub outgoing_session_id: u8,
    pub mtu: u32,
    pub window_size: u32,
    pub channel_count: u32,
    pub incoming_bandwidth: u32,
    pub outgoing_bandwidth: u32,
    pub packet_throttle_interval: u32,
    pub packet_throttle_accel: u32,
    pub packet_throttle_decel: u32,
    pub connect_id: u32,
}

/// ENet Disconnect Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetDisconnect {
    pub data: u32,
}

/// ENet Send Reliable Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetSendReliable {
    pub data_length: u16,
    pub data: Vec<u8>,
}

/// ENet Send Unreliable Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetSendUnreliable {
    pub unreliable_seq_num: u16,
    pub data_length: u16,
    pub data: Vec<u8>,
}

/// ENet Send Unsequenced Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetSendUnsequenced {
    pub unsequenced_group: u16,
    pub data_length: u16,
    pub data: Vec<u8>,
}

/// ENet Send Fragment Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetSendFragment {
    pub start_seq_num: u16,
    pub data_length: u16,
    pub fragment_count: u32,
    pub fragment_number: u32,
    pub total_length: u32,
    pub fragment_offset: u32,
    pub data: Vec<u8>,
}

/// ENet Bandwidth Limit Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetBandwidthLimit {
    pub incoming_bandwidth: u32,
    pub outgoing_bandwidth: u32,
}

/// ENet Throttle Configure Command
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct EnetThrottleConfigure {
    pub packet_throttle_interval: u32,
    pub packet_throttle_accel: u32,
    pub packet_throttle_decel: u32,
}

/// ENet Command Types
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum EnetCommandType {
    Acknowledge(EnetAcknowledge),
    Connect(EnetConnect),
    VerifyConnect(EnetVerifyConnect),
    Disconnect(EnetDisconnect),
    Ping,
    SendReliable(EnetSendReliable),
    SendUnreliable(EnetSendUnreliable),
    SendFragment(EnetSendFragment),
    SendUnsequenced(EnetSendUnsequenced),
    BandwidthLimit(EnetBandwidthLimit),
    ThrottleConfigure(EnetThrottleConfigure),
    SendUnreliableFragment,
}

impl EnetCommandType {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const CONNECT: u8 = 2;
    pub const VERIFY_CONNECT: u8 = 3;
    pub const DISCONNECT: u8 = 4;
    pub const PING: u8 = 5;
    pub const SEND_RELIABLE: u8 = 6;
    pub const SEND_UNRELIABLE: u8 = 7;
    pub const SEND_FRAGMENT: u8 = 8;
    pub const SEND_UNSEQUENCED: u8 = 9;
    pub const BANDWIDTH_LIMIT: u8 = 10;
    pub const THROTTLE_CONFIGURE: u8 = 11;
    pub const SEND_UNRELIABLE_FRAGMENT: u8 = 12;
}

/// A complete ENet command with header and payload
#[derive(Debug, Clone)]
pub struct EnetCommand {
    pub header: EnetCommandHeader,
    pub command_type: EnetCommandType,
}

/// A complete ENet packet with header and commands
#[derive(Debug, Clone)]
pub struct EnetPacket {
    pub header: EnetProtocolHeader,
    pub commands: Vec<EnetCommand>,
}

impl Display for EnetPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "PKT-(peer:{:4x},ts:{:4x})-cmd:[",
            self.header.peer_id,
            self.header.sent_time.unwrap_or_default()
        ))?;
        for cmd in &self.commands {
            f.write_fmt(format_args!("{},", cmd))?;
        }
        f.write_str("]")?;
        Ok(())
    }
}

impl Display for EnetCommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acknowledge(ack) => f.write_fmt(format_args!(
                "Ack(rsn:{},rst:{})",
                ack.received_reliable_seq_num, ack.received_sent_time
            )),
            Self::Connect(con) => f.write_fmt(format_args!("Connect{{{con:#?}}}")),
            Self::VerifyConnect(evc) => f.write_fmt(format_args!("VerifyConnect{{{evc:#?}}}")),
            Self::Disconnect(_) => f.write_fmt(format_args!("Disconnect")),
            Self::Ping => f.write_fmt(format_args!("Ping")),
            Self::SendReliable(data) => {
                f.write_fmt(format_args!("SendReliable[{}]", data.data_length))
            }
            Self::SendUnreliable(data) => {
                f.write_fmt(format_args!("SendUnreliable[{}]", data.data_length))
            }
            Self::SendFragment(_) => f.write_fmt(format_args!("SendFragment")),
            Self::SendUnsequenced(_) => f.write_fmt(format_args!("SendUnsequenced")),
            Self::BandwidthLimit(_) => f.write_fmt(format_args!("BandwidthLimit")),
            Self::ThrottleConfigure(_) => f.write_fmt(format_args!("ThrottleConfigure")),
            Self::SendUnreliableFragment => f.write_fmt(format_args!("SendUnreliableFragment")),
        }
    }
}

impl Display for EnetCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ch:{},rsn:{},cmd:{}}}",
            self.header.channel_id, self.header.reliable_seq_num, self.command_type
        )
    }
}

/// ENet protocol dissector
pub struct EnetDissector;

impl EnetDissector {
    /// Check if buffer has enough remaining bytes
    fn ensure_remaining(buf: &impl Buf, needed: usize) -> Result<(), EnetParseError> {
        let available = buf.remaining();
        if available < needed {
            return Err(EnetParseError::UnexpectedEof { needed, available });
        }
        Ok(())
    }

    /// Parse an ENet packet from a byte slice
    pub fn parse(data: &[u8]) -> Result<EnetPacket, EnetParseError> {
        let mut buf = data;

        // Parse protocol header
        Self::ensure_remaining(&buf, 2)?;
        let peer_id = buf.get_u16();

        // Check if sent_time is included (bit 0x8000 set in peer_id)
        let includes_sent_time = (peer_id & 0x8000) != 0;
        let sent_time = if includes_sent_time {
            Self::ensure_remaining(&buf, 2)?;
            Some(buf.get_u16())
        } else {
            None
        };

        let header = EnetProtocolHeader { peer_id, sent_time };
        let mut commands = Vec::new();

        // Parse commands
        while buf.has_remaining() {
            let command = Self::parse_command(&mut buf)?;
            commands.push(command);
        }

        Ok(EnetPacket { header, commands })
    }

    /// Parse a single command from the buffer
    fn parse_command(buf: &mut &[u8]) -> Result<EnetCommand, EnetParseError> {
        // Parse command header
        Self::ensure_remaining(buf, 4)?;
        let command_byte = buf.get_u8();
        let channel_id = buf.get_u8();
        let reliable_seq_num = buf.get_u16();

        let header = EnetCommandHeader {
            command: command_byte,
            channel_id,
            reliable_seq_num,
        };

        // Parse command-specific data based on command type (lower 4 bits)
        let command_type_id = command_byte & 0x0F;
        let command_type = match command_type_id {
            EnetCommandType::ACKNOWLEDGE => Self::parse_acknowledge(buf)?,
            EnetCommandType::CONNECT => Self::parse_connect(buf)?,
            EnetCommandType::VERIFY_CONNECT => Self::parse_verify_connect(buf)?,
            EnetCommandType::DISCONNECT => Self::parse_disconnect(buf)?,
            EnetCommandType::PING => EnetCommandType::Ping,
            EnetCommandType::SEND_RELIABLE => Self::parse_send_reliable(buf)?,
            EnetCommandType::SEND_UNRELIABLE => Self::parse_send_unreliable(buf)?,
            EnetCommandType::SEND_FRAGMENT => Self::parse_send_fragment(buf)?,
            EnetCommandType::SEND_UNSEQUENCED => Self::parse_send_unsequenced(buf)?,
            EnetCommandType::BANDWIDTH_LIMIT => Self::parse_bandwidth_limit(buf)?,
            EnetCommandType::THROTTLE_CONFIGURE => Self::parse_throttle_configure(buf)?,
            EnetCommandType::SEND_UNRELIABLE_FRAGMENT => EnetCommandType::SendUnreliableFragment,
            _ => return Err(EnetParseError::UnknownCommand(command_type_id)),
        };

        Ok(EnetCommand {
            header,
            command_type,
        })
    }

    fn parse_acknowledge(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 4)?;
        Ok(EnetCommandType::Acknowledge(EnetAcknowledge {
            received_reliable_seq_num: buf.get_u16(),
            received_sent_time: buf.get_u16(),
        }))
    }

    fn parse_connect(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 44)?;
        Ok(EnetCommandType::Connect(EnetConnect {
            outgoing_peer_id: buf.get_u16(),
            incoming_session_id: buf.get_u8(),
            outgoing_session_id: buf.get_u8(),
            mtu: buf.get_u32(),
            window_size: buf.get_u32(),
            channel_count: buf.get_u32(),
            incoming_bandwidth: buf.get_u32(),
            outgoing_bandwidth: buf.get_u32(),
            packet_throttle_interval: buf.get_u32(),
            packet_throttle_accel: buf.get_u32(),
            packet_throttle_decel: buf.get_u32(),
            connect_id: buf.get_u32(),
            data: buf.get_u32(),
        }))
    }

    fn parse_verify_connect(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 40)?;
        Ok(EnetCommandType::VerifyConnect(EnetVerifyConnect {
            outgoing_peer_id: buf.get_u16(),
            incoming_session_id: buf.get_u8(),
            outgoing_session_id: buf.get_u8(),
            mtu: buf.get_u32(),
            window_size: buf.get_u32(),
            channel_count: buf.get_u32(),
            incoming_bandwidth: buf.get_u32(),
            outgoing_bandwidth: buf.get_u32(),
            packet_throttle_interval: buf.get_u32(),
            packet_throttle_accel: buf.get_u32(),
            packet_throttle_decel: buf.get_u32(),
            connect_id: buf.get_u32(),
        }))
    }

    fn parse_disconnect(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 4)?;
        Ok(EnetCommandType::Disconnect(EnetDisconnect {
            data: buf.get_u32(),
        }))
    }

    fn parse_send_reliable(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 2)?;
        let data_length = buf.get_u16();

        Self::ensure_remaining(buf, data_length as usize)?;
        let mut data = vec![0u8; data_length as usize];
        buf.copy_to_slice(&mut data);

        Ok(EnetCommandType::SendReliable(EnetSendReliable {
            data_length,
            data,
        }))
    }

    fn parse_send_unreliable(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 4)?;
        let unreliable_seq_num = buf.get_u16();
        let data_length = buf.get_u16();

        Self::ensure_remaining(buf, data_length as usize)?;
        let mut data = vec![0u8; data_length as usize];
        buf.copy_to_slice(&mut data);

        Ok(EnetCommandType::SendUnreliable(EnetSendUnreliable {
            unreliable_seq_num,
            data_length,
            data,
        }))
    }

    fn parse_send_fragment(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 20)?;
        let start_seq_num = buf.get_u16();
        let data_length = buf.get_u16();
        let fragment_count = buf.get_u32();
        let fragment_number = buf.get_u32();
        let total_length = buf.get_u32();
        let fragment_offset = buf.get_u32();

        Self::ensure_remaining(buf, data_length as usize)?;
        let mut data = vec![0u8; data_length as usize];
        buf.copy_to_slice(&mut data);

        Ok(EnetCommandType::SendFragment(EnetSendFragment {
            start_seq_num,
            data_length,
            fragment_count,
            fragment_number,
            total_length,
            fragment_offset,
            data,
        }))
    }

    fn parse_send_unsequenced(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 4)?;
        let unsequenced_group = buf.get_u16();
        let data_length = buf.get_u16();

        Self::ensure_remaining(buf, data_length as usize)?;
        let mut data = vec![0u8; data_length as usize];
        buf.copy_to_slice(&mut data);

        Ok(EnetCommandType::SendUnsequenced(EnetSendUnsequenced {
            unsequenced_group,
            data_length,
            data,
        }))
    }

    fn parse_bandwidth_limit(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 8)?;
        Ok(EnetCommandType::BandwidthLimit(EnetBandwidthLimit {
            incoming_bandwidth: buf.get_u32(),
            outgoing_bandwidth: buf.get_u32(),
        }))
    }

    fn parse_throttle_configure(buf: &mut &[u8]) -> Result<EnetCommandType, EnetParseError> {
        Self::ensure_remaining(buf, 12)?;
        Ok(EnetCommandType::ThrottleConfigure(EnetThrottleConfigure {
            packet_throttle_interval: buf.get_u32(),
            packet_throttle_accel: buf.get_u32(),
            packet_throttle_decel: buf.get_u32(),
        }))
    }
}

pub struct EnetSerializer;

impl EnetSerializer {
    pub fn serialize(packet: &EnetPacket) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::write_header(&mut buf, &packet.header);
        for command in &packet.commands {
            Self::write_command(&mut buf, command);
        }
        buf
    }

    fn write_header(buf: &mut Vec<u8>, header: &EnetProtocolHeader) {
        buf.put_u16(header.peer_id);
        if let Some(sent_time) = header.sent_time {
            buf.put_u16(sent_time);
        }
    }

    fn write_command(buf: &mut Vec<u8>, command: &EnetCommand) {
        buf.put_u8(command.header.command);
        buf.put_u8(command.header.channel_id);
        buf.put_u16(command.header.reliable_seq_num);
        Self::write_command_type(buf, &command.command_type);
    }

    fn write_command_type(buf: &mut Vec<u8>, command_type: &EnetCommandType) {
        match command_type {
            EnetCommandType::Acknowledge(ack) => Self::write_acknowledge(buf, ack),
            EnetCommandType::Connect(con) => Self::write_connect(buf, con),
            EnetCommandType::VerifyConnect(vc) => Self::write_verify_connect(buf, vc),
            EnetCommandType::Disconnect(disc) => Self::write_disconnect(buf, disc),
            EnetCommandType::Ping => {}
            EnetCommandType::SendReliable(sr) => Self::write_send_reliable(buf, sr),
            EnetCommandType::SendUnreliable(su) => Self::write_send_unreliable(buf, su),
            EnetCommandType::SendFragment(sf) => Self::write_send_fragment(buf, sf),
            EnetCommandType::SendUnsequenced(sus) => Self::write_send_unsequenced(buf, sus),
            EnetCommandType::BandwidthLimit(bl) => Self::write_bandwidth_limit(buf, bl),
            EnetCommandType::ThrottleConfigure(tc) => Self::write_throttle_configure(buf, tc),
            EnetCommandType::SendUnreliableFragment => {}
        }
    }

    fn write_acknowledge(buf: &mut Vec<u8>, ack: &EnetAcknowledge) {
        buf.put_u16(ack.received_reliable_seq_num);
        buf.put_u16(ack.received_sent_time);
    }

    fn write_connect(buf: &mut Vec<u8>, con: &EnetConnect) {
        buf.put_u16(con.outgoing_peer_id);
        buf.put_u8(con.incoming_session_id);
        buf.put_u8(con.outgoing_session_id);
        buf.put_u32(con.mtu);
        buf.put_u32(con.window_size);
        buf.put_u32(con.channel_count);
        buf.put_u32(con.incoming_bandwidth);
        buf.put_u32(con.outgoing_bandwidth);
        buf.put_u32(con.packet_throttle_interval);
        buf.put_u32(con.packet_throttle_accel);
        buf.put_u32(con.packet_throttle_decel);
        buf.put_u32(con.connect_id);
        buf.put_u32(con.data);
    }

    fn write_verify_connect(buf: &mut Vec<u8>, vc: &EnetVerifyConnect) {
        buf.put_u16(vc.outgoing_peer_id);
        buf.put_u8(vc.incoming_session_id);
        buf.put_u8(vc.outgoing_session_id);
        buf.put_u32(vc.mtu);
        buf.put_u32(vc.window_size);
        buf.put_u32(vc.channel_count);
        buf.put_u32(vc.incoming_bandwidth);
        buf.put_u32(vc.outgoing_bandwidth);
        buf.put_u32(vc.packet_throttle_interval);
        buf.put_u32(vc.packet_throttle_accel);
        buf.put_u32(vc.packet_throttle_decel);
        buf.put_u32(vc.connect_id);
    }

    fn write_disconnect(buf: &mut Vec<u8>, disc: &EnetDisconnect) {
        buf.put_u32(disc.data);
    }

    fn write_send_reliable(buf: &mut Vec<u8>, sr: &EnetSendReliable) {
        buf.put_u16(sr.data_length);
        buf.put_slice(&sr.data);
    }

    fn write_send_unreliable(buf: &mut Vec<u8>, su: &EnetSendUnreliable) {
        buf.put_u16(su.unreliable_seq_num);
        buf.put_u16(su.data_length);
        buf.put_slice(&su.data);
    }

    fn write_send_fragment(buf: &mut Vec<u8>, sf: &EnetSendFragment) {
        buf.put_u16(sf.start_seq_num);
        buf.put_u16(sf.data_length);
        buf.put_u32(sf.fragment_count);
        buf.put_u32(sf.fragment_number);
        buf.put_u32(sf.total_length);
        buf.put_u32(sf.fragment_offset);
        buf.put_slice(&sf.data);
    }

    fn write_send_unsequenced(buf: &mut Vec<u8>, sus: &EnetSendUnsequenced) {
        buf.put_u16(sus.unsequenced_group);
        buf.put_u16(sus.data_length);
        buf.put_slice(&sus.data);
    }

    fn write_bandwidth_limit(buf: &mut Vec<u8>, bl: &EnetBandwidthLimit) {
        buf.put_u32(bl.incoming_bandwidth);
        buf.put_u32(bl.outgoing_bandwidth);
    }

    fn write_throttle_configure(buf: &mut Vec<u8>, tc: &EnetThrottleConfigure) {
        buf.put_u32(tc.packet_throttle_interval);
        buf.put_u32(tc.packet_throttle_accel);
        buf.put_u32(tc.packet_throttle_decel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(command_type: EnetCommandType, command_id: u8) -> EnetPacket {
        EnetPacket {
            header: EnetProtocolHeader {
                peer_id: 0x8001,
                sent_time: Some(0x1234),
            },
            commands: vec![EnetCommand {
                header: EnetCommandHeader {
                    command: command_id,
                    channel_id: 0,
                    reliable_seq_num: 1,
                },
                command_type,
            }],
        }
    }

    fn roundtrip(packet: &EnetPacket) -> EnetPacket {
        let serialized = EnetSerializer::serialize(packet);
        EnetDissector::parse(&serialized).unwrap()
    }

    #[test]
    fn test_acknowledge_roundtrip() {
        let packet = make_packet(
            EnetCommandType::Acknowledge(EnetAcknowledge {
                received_reliable_seq_num: 42,
                received_sent_time: 1000,
            }),
            EnetCommandType::ACKNOWLEDGE,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        assert_eq!(packet.commands.len(), parsed.commands.len());
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::Acknowledge(a), EnetCommandType::Acknowledge(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_connect_roundtrip() {
        let packet = make_packet(
            EnetCommandType::Connect(EnetConnect {
                outgoing_peer_id: 1,
                incoming_session_id: 2,
                outgoing_session_id: 3,
                mtu: 1400,
                window_size: 32768,
                channel_count: 2,
                incoming_bandwidth: 0,
                outgoing_bandwidth: 0,
                packet_throttle_interval: 5000,
                packet_throttle_accel: 2,
                packet_throttle_decel: 2,
                connect_id: 12345,
                data: 0,
            }),
            EnetCommandType::CONNECT,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::Connect(a), EnetCommandType::Connect(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_verify_connect_roundtrip() {
        let packet = make_packet(
            EnetCommandType::VerifyConnect(EnetVerifyConnect {
                outgoing_peer_id: 1,
                incoming_session_id: 2,
                outgoing_session_id: 3,
                mtu: 1400,
                window_size: 32768,
                channel_count: 2,
                incoming_bandwidth: 0,
                outgoing_bandwidth: 0,
                packet_throttle_interval: 5000,
                packet_throttle_accel: 2,
                packet_throttle_decel: 2,
                connect_id: 12345,
            }),
            EnetCommandType::VERIFY_CONNECT,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::VerifyConnect(a), EnetCommandType::VerifyConnect(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_disconnect_roundtrip() {
        let packet = make_packet(
            EnetCommandType::Disconnect(EnetDisconnect { data: 999 }),
            EnetCommandType::DISCONNECT,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::Disconnect(a), EnetCommandType::Disconnect(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_ping_roundtrip() {
        let packet = make_packet(EnetCommandType::Ping, EnetCommandType::PING);
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        assert!(matches!(
            parsed.commands[0].command_type,
            EnetCommandType::Ping
        ));
    }

    #[test]
    fn test_send_reliable_roundtrip() {
        let data = vec![1, 2, 3, 4, 5];
        let packet = make_packet(
            EnetCommandType::SendReliable(EnetSendReliable {
                data_length: data.len() as u16,
                data: data.clone(),
            }),
            EnetCommandType::SEND_RELIABLE,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::SendReliable(a), EnetCommandType::SendReliable(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_send_unreliable_roundtrip() {
        let data = vec![10, 20, 30];
        let packet = make_packet(
            EnetCommandType::SendUnreliable(EnetSendUnreliable {
                unreliable_seq_num: 7,
                data_length: data.len() as u16,
                data: data.clone(),
            }),
            EnetCommandType::SEND_UNRELIABLE,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::SendUnreliable(a), EnetCommandType::SendUnreliable(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_send_fragment_roundtrip() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let packet = make_packet(
            EnetCommandType::SendFragment(EnetSendFragment {
                start_seq_num: 100,
                data_length: data.len() as u16,
                fragment_count: 4,
                fragment_number: 1,
                total_length: 1000,
                fragment_offset: 256,
                data: data.clone(),
            }),
            EnetCommandType::SEND_FRAGMENT,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::SendFragment(a), EnetCommandType::SendFragment(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_send_unsequenced_roundtrip() {
        let data = vec![0x11, 0x22];
        let packet = make_packet(
            EnetCommandType::SendUnsequenced(EnetSendUnsequenced {
                unsequenced_group: 5,
                data_length: data.len() as u16,
                data: data.clone(),
            }),
            EnetCommandType::SEND_UNSEQUENCED,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::SendUnsequenced(a), EnetCommandType::SendUnsequenced(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_bandwidth_limit_roundtrip() {
        let packet = make_packet(
            EnetCommandType::BandwidthLimit(EnetBandwidthLimit {
                incoming_bandwidth: 100000,
                outgoing_bandwidth: 50000,
            }),
            EnetCommandType::BANDWIDTH_LIMIT,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::BandwidthLimit(a), EnetCommandType::BandwidthLimit(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_throttle_configure_roundtrip() {
        let packet = make_packet(
            EnetCommandType::ThrottleConfigure(EnetThrottleConfigure {
                packet_throttle_interval: 5000,
                packet_throttle_accel: 2,
                packet_throttle_decel: 2,
            }),
            EnetCommandType::THROTTLE_CONFIGURE,
        );
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        match (
            &packet.commands[0].command_type,
            &parsed.commands[0].command_type,
        ) {
            (EnetCommandType::ThrottleConfigure(a), EnetCommandType::ThrottleConfigure(b)) => {
                assert_eq!(a, b);
            }
            _ => panic!("command type mismatch"),
        }
    }

    #[test]
    fn test_packet_without_sent_time() {
        let packet = EnetPacket {
            header: EnetProtocolHeader {
                peer_id: 0x0001,
                sent_time: None,
            },
            commands: vec![EnetCommand {
                header: EnetCommandHeader {
                    command: EnetCommandType::PING,
                    channel_id: 0,
                    reliable_seq_num: 1,
                },
                command_type: EnetCommandType::Ping,
            }],
        };
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
    }

    #[test]
    fn test_multiple_commands() {
        let packet = EnetPacket {
            header: EnetProtocolHeader {
                peer_id: 0x8002,
                sent_time: Some(5000),
            },
            commands: vec![
                EnetCommand {
                    header: EnetCommandHeader {
                        command: EnetCommandType::PING,
                        channel_id: 0,
                        reliable_seq_num: 1,
                    },
                    command_type: EnetCommandType::Ping,
                },
                EnetCommand {
                    header: EnetCommandHeader {
                        command: EnetCommandType::ACKNOWLEDGE,
                        channel_id: 0,
                        reliable_seq_num: 2,
                    },
                    command_type: EnetCommandType::Acknowledge(EnetAcknowledge {
                        received_reliable_seq_num: 100,
                        received_sent_time: 4000,
                    }),
                },
            ],
        };
        let parsed = roundtrip(&packet);
        assert_eq!(packet.header, parsed.header);
        assert_eq!(packet.commands.len(), parsed.commands.len());
    }
}
