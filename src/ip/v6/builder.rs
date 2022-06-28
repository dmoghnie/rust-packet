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




use std::net::Ipv6Addr;

use crate::{error::*};
use crate::buffer::{self, Buffer};
use crate::builder::{Builder as Build, Finalization};
use crate::packet::{AsPacket, AsPacketMut};
use crate::ip::v6::Packet;
/// IPv6 packet builder.
pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,
	payload: bool
}

impl<B: Buffer> Build<B> for Builder<B> {
	// fn with(buffer: B) -> Result<Self> {
	// 	use crate::size::header::Min;
	// 	buffer.next(Packet::<()>::min())?;

	// 	Ok(Builder {
	// 		buffer:    buffer,
	// 		finalizer: Default::default(),
	// 		payload: false
	// 	})
	// }
fn with(mut buffer: B) -> Result<Self> {
		use crate::size::header::Min;
		buffer.next(Packet::<()>::min())?;

		buffer.data_mut()[0] = (6 << 4);

		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),
			payload: false,
		})
	}
	fn finalizer(&mut self) -> &mut Finalization {
		&mut self.finalizer
	}

	fn build(mut self) -> Result<B::Inner> {
		self.prepare();
		
		let mut buffer = self.buffer.into_inner();
		self.finalizer.finalize(buffer.as_mut())?;
		Ok(buffer)
	}
	
}

impl<B: Buffer> Builder<B> {
	fn prepare(&mut self) {
		let offset = self.buffer.offset();
		self.finalizer.add(move |out| {
			// Set the version to 6 and the header length.
			let old = out[offset];
			out[offset] = (6 << 4) | (old & 0b0000_1111);

			Ok(())
		});
	}
}

impl Default for Builder<buffer::Dynamic> {
	fn default() -> Self {
		Builder::with(buffer::Dynamic::default()).unwrap()
	}
}
impl<'a, B: Buffer> AsPacket<'a, Packet<&'a [u8]>> for Builder<B> {
	fn as_packet(&self) -> Result<Packet<&[u8]>> {
		Packet::new(self.buffer.data())
	}
}

impl<'a, B: Buffer> AsPacketMut<'a, Packet<&'a mut [u8]>> for Builder<B> {
	fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
		Packet::new(self.buffer.data_mut())
	}
}

impl <B: Buffer> Builder<B> {
	pub fn traffic_class(mut self, value: u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_traffic_class(value)?;
		Ok(self)
	}
	pub fn flow_label(mut self, value:u32) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_flow_label(value)?;
		Ok(self)
	}
	pub fn payload_length(mut self, value: u16) ->Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_payload_length(value)?;
		Ok(self)
	}
	pub fn next_header(mut self, value:u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_next_header(value)?;
		Ok(self)
	}
	pub fn hop_limit(mut self, value: u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_hop_limit(value)?;
		Ok(self)
	}
	pub fn source(mut self, value: Ipv6Addr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_source(value)?;
		Ok(self)
	}
	pub fn destination(mut self, value: Ipv6Addr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_destination(value)?;
		Ok(self)
	}
	/// Payload for the packet.
	pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
		if self.payload {
			Err(Error::AlreadyDefined)?
		}

		self.payload = true;

		let mut len = 0u16;

		for byte in value {
			len += 1;
			self.buffer.more(1)?;
			*self.buffer.data_mut().last_mut().unwrap() = *byte;
		}
		self = self.payload_length(len).unwrap();

		Ok(self)
	}
}