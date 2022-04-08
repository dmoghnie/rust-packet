//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use crate::error::*;
use crate::packet::{AsPacket, AsPacketMut, Packet as P, PacketMut as PM};
use std::fmt;
use std::net::Ipv6Addr;

/// IPv6 packet parser.
#[derive(Clone)]
pub struct Packet<B> {
    buffer: B,
}

sized!(Packet,
header {
    min:  40,
    max:  40,
    size: 40,
}

payload {
    min:  0,
    max:  u16::max_value() as usize - 40,
    size: p => (p.payload_length() as usize).saturating_sub(40),
});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ip::v6::Packet")
            .field("version", &self.version())
            .field("traffic class", &self.traffic_class())
            .field("flow label", &self.flow_label())
            .field("payload length", &self.payload_length())
            .field("next header", &self.next_header())
            .field("hot limit", &self.hop_limit())
            .field("source", &self.source())
            .field("destination", &self.destination())
            .finish()
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Create an IPv6 packet without checking the buffer.
    pub fn unchecked(buffer: B) -> Packet<B> {
        Packet { buffer }
    }

    /// Parse an IPv6 packet without checking the payload.
    pub fn no_payload(buffer: B) -> Result<Packet<B>> {
        use crate::size::header::Min;

        let packet = Packet::unchecked(buffer);

        if packet.buffer.as_ref().len() < Self::min() {
            Err(Error::SmallBuffer)?
        }

        if packet.buffer.as_ref()[0] >> 4 != 6 {
            Err(Error::InvalidPacket)?
        }

        Ok(packet)
    }

    /// Parse an IPv6 packet, checking the buffer contents are correct.
    pub fn new(buffer: B) -> Result<Packet<B>> {
        let packet = Packet::no_payload(buffer)?;

        if packet.buffer.as_ref().len() < packet.payload_length() as usize {
            Err(Error::SmallBuffer)?
        }

        Ok(packet)
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Convert the packet to its owned version.
    ///
    /// # Notes
    ///
    /// It would be nice if `ToOwned` could be implemented, but `Packet` already
    /// implements `Clone` and the impl would conflict.
    pub fn to_owned(&self) -> Packet<Vec<u8>> {
        Packet::unchecked(self.buffer.as_ref().to_vec())
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
    fn as_ref(&self) -> &[u8] {
        use crate::size::Size;

        &self.buffer.as_ref()[..self.size()]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        use crate::size::Size;

        let size = self.size();
        &mut self.buffer.as_mut()[..size]
    }
}

impl<'a, B: AsRef<[u8]>> AsPacket<'a, Packet<&'a [u8]>> for B {
    fn as_packet(&self) -> Result<Packet<&[u8]>> {
        Packet::new(self.as_ref())
    }
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> AsPacketMut<'a, Packet<&'a mut [u8]>> for B {
    fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
        Packet::new(self.as_mut())
    }
}

impl<B: AsRef<[u8]>> P for Packet<B> {
    fn split(&self) -> (&[u8], &[u8]) {
        self.buffer.as_ref().split_at(40)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
    fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
        self.buffer.as_mut().split_at_mut(40)
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// IP protocol version, will always be 6.
    pub fn version(&self) -> u8 {
        self.buffer.as_ref()[0] >> 4
    }

    ///  The 8-bit Traffic Class field in 8-bit.
    pub fn traffic_class(&self) -> u8 {
        self.buffer.as_ref()[0] << 4 | self.buffer.as_ref()[1] >> 4
    }

    /// The flow label in 20-bit.
    pub fn flow_label(&self) -> u32 {
        ((self.buffer.as_ref()[1] as u32) << 16
            | (self.buffer.as_ref()[2] as u32) << 8
            | self.buffer.as_ref()[3] as u32)
            & 0b1111_1111_1111_1111_1111
    }

    /// The length of the Ipv6 payload.
    pub fn payload_length(&self) -> u16 {
        (self.buffer.as_ref()[4] as u16) << 8 | (self.buffer.as_ref()[5] as u16)
    }

    /// Total length of the packet in octets.
    pub fn next_header(&self) -> u8 {
        self.buffer.as_ref()[6]
    }

    /// ID of the packet.
    pub fn hop_limit(&self) -> u8 {
        self.buffer.as_ref()[7]
    }

    /// ID of the packet.
    pub fn source(&self) -> Ipv6Addr {
        Ipv6Addr::from([
            self.buffer.as_ref()[8],
            self.buffer.as_ref()[9],
            self.buffer.as_ref()[10],
            self.buffer.as_ref()[11],
            self.buffer.as_ref()[12],
            self.buffer.as_ref()[13],
            self.buffer.as_ref()[14],
            self.buffer.as_ref()[15],
            self.buffer.as_ref()[16],
            self.buffer.as_ref()[17],
            self.buffer.as_ref()[18],
            self.buffer.as_ref()[19],
            self.buffer.as_ref()[20],
            self.buffer.as_ref()[21],
            self.buffer.as_ref()[22],
            self.buffer.as_ref()[23],
        ])
    }

    /// Flags of the packet.
    pub fn destination(&self) -> Ipv6Addr {
        Ipv6Addr::from([
            self.buffer.as_ref()[24],
            self.buffer.as_ref()[25],
            self.buffer.as_ref()[26],
            self.buffer.as_ref()[27],
            self.buffer.as_ref()[28],
            self.buffer.as_ref()[29],
            self.buffer.as_ref()[30],
            self.buffer.as_ref()[31],
            self.buffer.as_ref()[32],
            self.buffer.as_ref()[33],
            self.buffer.as_ref()[34],
            self.buffer.as_ref()[35],
            self.buffer.as_ref()[36],
            self.buffer.as_ref()[37],
            self.buffer.as_ref()[38],
            self.buffer.as_ref()[39],
        ])
    }
}
