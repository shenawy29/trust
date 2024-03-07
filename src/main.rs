mod tcp;

use std::io;

use std::{collections::HashMap, net::Ipv4Addr};
use tun_tap::{Iface, Mode};

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dest: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut nic = Iface::without_packet_info("tun0", Mode::Tun)?;
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf)?;

        if etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]).is_err() {
            eprintln!("Weird packet.");
            continue;
        };

        let ip_header = etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]).unwrap();

        let src = ip_header.source_addr();
        let dest = ip_header.destination_addr();

        // if not a TCP packet, skip
        if ip_header.protocol().0 != 0x06 {
            continue;
        }

        match etherparse::TcpHeaderSlice::from_slice(&buf[ip_header.slice().len()..nbytes]) {
            Ok(tcp_header) => {
                // index of first byte of payload data
                let datai = ip_header.slice().len() + tcp_header.slice().len();

                match connections.entry(Quad {
                    src: (src, tcp_header.source_port()),
                    dest: (dest, tcp_header.destination_port()),
                }) {
                    std::collections::hash_map::Entry::Occupied(mut c) => {
                        c.get_mut().on_packet(
                            &mut nic,
                            ip_header,
                            tcp_header,
                            &buf[datai..nbytes],
                        )?;
                    }
                    std::collections::hash_map::Entry::Vacant(e) => {
                        if let Some(c) = tcp::Connection::accept(
                            &mut nic,
                            ip_header,
                            tcp_header,
                            &buf[datai..nbytes],
                        )? {
                            e.insert(c);
                        }
                    }
                }
            }
            Err(_) => eprintln!("Weird packet."),
        }
    }
}
