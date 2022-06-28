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
    size: p => (p.payload_length()) as usize,
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

impl Default for Packet<crate::buffer::Dynamic> {
    fn default() -> Self {        
        use crate::buffer::Dynamic;
        let mut buffer = Dynamic::default();
        
        buffer[0] = (6 << 4);
        Self { buffer }
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
impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
    pub fn set_traffic_class(&mut self, value: u8) -> Result<&mut Self> {
        let old0 = self.buffer.as_ref()[0];
        let old1 = self.buffer.as_ref()[1];
        self.buffer.as_mut()[0] = (old0 & 0b1111_0000) | ((value & 0b1111_0000) >> 4);
        self.buffer.as_mut()[1] = (old1 & 0b0000_1111) | ((value & 0b0000_1111) << 4);

        Ok(self)
    }
    /// The flow label in 20-bit.
    pub fn set_flow_label(&mut self, value: u32) -> Result<&mut Self> {
        let b = value.to_be_bytes();
        let old1 = self.buffer.as_ref()[1];

        self.buffer.as_mut()[1] = (old1 & 0b1111_0000) | (b[1] & 0b0000_1111);
        self.buffer.as_mut()[2] = b[2];
        self.buffer.as_mut()[3] = b[3];

        Ok(self)
    }
    pub fn set_payload_length(&mut self, value: u16) -> Result<&mut Self> {
        let b = value.to_be_bytes();
        self.buffer.as_mut()[4] = b[0];
        self.buffer.as_mut()[5] = b[1];

        Ok(self)
    }
    pub fn set_next_header(&mut self, value: u8) -> Result<&mut Self> {
        self.buffer.as_mut()[6] = value;
        Ok(self)
    }

    pub fn set_hop_limit(&mut self, value: u8) -> Result<&mut Self> {
        self.buffer.as_mut()[7] = value;

        Ok(self)
    }

    pub fn set_source(&mut self, value: Ipv6Addr) -> Result<&mut Self> {
        self.buffer.as_mut()[8..24].copy_from_slice(&value.octets());

        Ok(self)
    }
    pub fn set_destination(&mut self, value: Ipv6Addr) -> Result<&mut Self> {
        self.buffer.as_mut()[24..40].copy_from_slice(&value.octets());

        Ok(self)
    }
    pub fn checked(&mut self) -> Checked<'_, B> {
        Checked { packet: self }
    }
}
pub struct Checked<'a, B: AsRef<[u8]> + AsMut<[u8]>> {
    packet: &'a mut Packet<B>,
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]> + 'a> Checked<'a, B> {
    pub fn set_traffic_class(&mut self, value: u8) -> Result<&mut Self> {
        self.packet.set_traffic_class(value)?;

        Ok(self)
    }
    /// The flow label in 20-bit.
    pub fn set_flow_label(&mut self, value: u32) -> Result<&mut Self> {
        self.packet.set_flow_label(value)?;

        Ok(self)
    }
    pub fn set_payload_length(&mut self, value: u16) -> Result<&mut Self> {
        self.packet.set_payload_length(value)?;

        Ok(self)
    }
    pub fn set_next_header(&mut self, value: u8) -> Result<&mut Self> {
        self.packet.set_next_header(value)?;

        Ok(self)
    }

    pub fn set_hop_limit(&mut self, value: u8) -> Result<&mut Self> {
        self.packet.set_hop_limit(value)?;

        Ok(self)
    }

    pub fn set_source(&mut self, value: Ipv6Addr) -> Result<&mut Self> {
        self.packet.set_source(value)?;

        Ok(self)
    }
    pub fn set_destination(&mut self, value: Ipv6Addr) -> Result<&mut Self> {
        self.packet.set_destination(value)?;

        Ok(self)
    }
}

// impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> Drop for Checked<'a, B> {
// 	fn drop(&mut self) {
// 		self.packet.update_checksum().unwrap();
// 	}
// }

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;

    use crate::AsPacket;
    use crate::Builder;
    use crate::PacketMut;
    use crate::ether;
    use crate::ip;
    use crate::packet::Packet;
    use crate::udp;

    #[test]
    fn values() {
        let raw = [
            0x00u8, 0x23, 0x69, 0x63, 0x59, 0xbe, 0xe4, 0xb3, 0x18, 0x26, 0x63, 0xa3, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8,
            0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8,
            0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61,
            0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65,
            0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01,
        ];

        let ether = ether::Packet::new(&raw[..]).unwrap();
        let ip = ip::v4::Packet::new(ether.payload()).unwrap();
        let udp = udp::Packet::new(ip.payload()).unwrap();

        assert!(ip.is_valid());
        assert!(udp.is_valid(&ip::Packet::from(&ip)));

        assert_eq!(ether.destination(), "00:23:69:63:59:be".parse().unwrap());
        assert_eq!(ether.source(), "e4:b3:18:26:63:a3".parse().unwrap());
        assert_eq!(ether.protocol(), ether::Protocol::Ipv4);
    }

    #[test]
    fn values_ipv6() {
        let raw = hex::decode("30b5c2eb4cb0080027aff83f86dd60000000005c11ff2607f2c0f00fb00100000000faceb00c200105900000000000000000451f1f6210f610f6005c464e15000001fb7aff572ebc6869000199101f5000022607f2c0f00fb00100000000faceb00c001c000199101f5000000005011c10000000000199101f500164ff00000500022607f2c0f00fb00100000000faceb00c").unwrap();
        let ether = ether::Packet::new(&raw[..]).unwrap();
        let ip = ip::v6::Packet::new(ether.payload()).unwrap();
        let _ = udp::Packet::new(ip.payload()).unwrap();

        assert_eq!(ether.destination(), "30:b5:c2:eb:4c:b0".parse().unwrap());
        assert_eq!(ether.source(), "08:00:27:af:f8:3f".parse().unwrap());
        assert_eq!(
            ip.source(),
            "2607:f2c0:f00f:b001::face:b00c"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(
            ip.destination(),
            "2001:590::451f:1f62".parse::<Ipv6Addr>().unwrap()
        );


        assert_eq!(ether.protocol(), ether::Protocol::Ipv6);
    }

    #[test]
    fn values_set_ipv6() {
        let mut raw = hex::decode("30b5c2eb4cb0080027aff83f86dd60000000005c11ff2607f2c0f00fb00100000000faceb00c200105900000000000000000451f1f6210f610f6005c464e15000001fb7aff572ebc6869000199101f5000022607f2c0f00fb00100000000faceb00c001c000199101f5000000005011c10000000000199101f500164ff00000500022607f2c0f00fb00100000000faceb00c").unwrap();
        let mut ether = ether::Packet::new(&mut raw[..]).unwrap();
        let mut ip = ip::v6::Packet::no_payload(ether.payload_mut()).unwrap();
        

        assert_eq!(
            ip.source(),
            "2607:f2c0:f00f:b001::face:b00c"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(
            ip.destination(),
            "2001:590::451f:1f62".parse::<Ipv6Addr>().unwrap()
        );

        ip.set_destination("2001:590::451f:1f61".parse::<Ipv6Addr>().unwrap());

        assert_eq!(ip.destination(), "2001:590::451f:1f61".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn builder() {
        let mut raw = hex::decode("30b5c2eb4cb0080027aff83f86dd60000000005c11ff2607f2c0f00fb00100000000faceb00c200105900000000000000000451f1f6210f610f6005c464e15000001fb7aff572ebc6869000199101f5000022607f2c0f00fb00100000000faceb00c001c000199101f5000000005011c10000000000199101f500164ff00000500022607f2c0f00fb00100000000faceb00c").unwrap();
        let mut ether = ether::Packet::new(&mut raw[..]).unwrap();
        let mut ip = ip::v6::Packet::no_payload(ether.payload_mut()).unwrap();

        let new_ip = ip::v6::Builder::default().traffic_class(ip.traffic_class())
        .unwrap().destination(ip.destination())
        .unwrap().next_header(ip.next_header())
        .unwrap().flow_label(ip.flow_label())
        .unwrap().source(ip.source())
        .unwrap().hop_limit(ip.hop_limit())
        .unwrap().payload(ip.payload())
        .unwrap().build().unwrap();        
        assert_eq!(ip.as_ref().to_vec(), new_ip);
    }
}
