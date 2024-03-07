use std::io;

pub enum State {
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip_packet: etherparse::Ipv4Header,
}

#[derive(Default)]
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

#[derive(Default)]
struct RecvSequenceSpace {
    /// The next byte to be recieved from the client.
    nxt: u32,
    /// The client's window size.
    wnd: u16,
    /// client's urgent pointer.
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept(
        nic: &mut tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<Option<Self>> {
        let mut mtu_buffer = [0u8; 1500];

        if !tcp_header.syn() {
            return Ok(None);
        }

        let iss = 0;

        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss: 0,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                // TODO: make it tcp_header.urg();
                up: false,
            },
            ip_packet: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpNumber::TCP,
                ip_header.destination(),
                ip_header.source(),
            )
            .expect("Failed to create IP packet."),
        };

        let mut syn_ack = etherparse::TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            c.send.iss,
            c.send.wnd,
        );

        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        c.ip_packet.set_payload_len(syn_ack.header_len()).unwrap();

        let unwritten = {
            let mut unwritten = &mut mtu_buffer[..];

            c.ip_packet.write(&mut unwritten)?;

            syn_ack.write(&mut unwritten)?;

            unwritten.len()
        };

        nic.send(&mtu_buffer[..unwritten])?;
        Ok(Some(c))
    }

    pub fn on_packet(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        let ackn = tcp_header.acknowledgment_number();

        if self.send.una < ackn {
            if ackn <= self.send.nxt {
                // nowrapping
            } else {
            }
        }

        match self.state {
            State::SynRcvd => {
                todo!()
            }
            State::Estab => {
                todo!()
            }
        }

        Ok(())
    }
}
