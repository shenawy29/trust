use std::io;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

impl Default for State {
    fn default() -> Self {
        State::Closed
    }
}

impl State {
    pub fn on_packet(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        let mut mtu_buffer = [0u8; 1500];

        match self {
            State::Closed => Ok(0),
            State::Listen => {
                // expect a syn packet when listening for incoming connections.
                if !tcp_header.syn() {
                    return Ok(0);
                }

                let mut syn_ack = etherparse::TcpHeader::new(
                    tcp_header.destination_port(),
                    tcp_header.source_port(),
                    unimplemented!(),
                    unimplemented!(),
                );

                syn_ack.syn = true;
                syn_ack.ack = true;

                let mut ip_packet = etherparse::Ipv4Header::new(
                    syn_ack.header_len_u16(),
                    64,
                    etherparse::IpNumber::TCP,
                    ip_header.destination(),
                    ip_header.source(),
                );

                let unwritten = {
                    let mut unwritten = &mut mtu_buffer[..];
                    if let Ok(packet) = ip_packet {
                        packet.write(&mut unwritten);
                    } else {
                        // TODO: Make this an error
                        return Ok(0);
                    }

                    syn_ack.write(&mut unwritten)?;

                    unwritten.len()
                };

                nic.send(&mtu_buffer[..unwritten])
            }

            State::SynRcvd => todo!(),
            State::Estab => todo!(),
        }
    }
}
