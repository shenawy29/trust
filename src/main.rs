mod tcp;

use std::{collections::HashMap, io, net::Ipv4Addr};
use tun_tap::{Iface, Mode};

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dest: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut nic = Iface::new("tun0", Mode::Tun)?;
    let mut connections: HashMap<Quad, tcp::State> = Default::default();
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf)?;

        let _frame_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let frame_protocol = u16::from_be_bytes([buf[2], buf[3]]);

        // If not an ipv4 packet, skip
        if frame_protocol != 0x0800 {
            continue;
        }

        // check if ipv4 packet is ok
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            //get an IP header
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dest = ip_header.destination_addr();

                // if not an TCP packet, skip
                if ip_header.protocol().0 != 0x06 {
                    continue;
                }

                // check if TCP packet is ok
                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[4 + ip_header.slice().len()..nbytes],
                ) {
                    // get a tcp header
                    Ok(tcp_header) => {
                        // index of first byte of payload data
                        let datai = 4 + ip_header.slice().len() + tcp_header.slice().len();

                        // add to list of active connections
                        connections
                            .entry(Quad {
                                src: (src, tcp_header.source_port()),
                                dest: (dest, tcp_header.destination_port()),
                            })
                            .or_default()
                            .on_packet(&mut nic, ip_header, tcp_header, &buf[datai..nbytes]);
                    }

                    Err(e) => eprintln!("Ignoring weird tcp packet {:?}", e),
                }
            }

            Err(e) => eprintln!("Ignoring packet {:?}", e),
        }
    }
}
