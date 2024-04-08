use bitflags::bitflags;
use std::{
    cmp::min,
    collections::{BTreeMap, VecDeque},
    io::{self, Write},
    time,
};
use tun_tap::Iface;

use std::io::Result;

bitflags! {
    pub(crate) struct Available: u32 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

#[derive(Debug)]
enum State {
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip_h: etherparse::Ipv4Header,
    tcp_h: etherparse::TcpHeader,
    timers: Timers,

    pub(crate) unacked: VecDeque<u8>,
    pub(crate) incoming: VecDeque<u8>,

    pub(crate) closed: bool,
    closed_at: Option<u32>,
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: f64,
}

impl Connection {
    pub fn is_recv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            true
        } else {
            false
        }
    }

    pub fn availability(&self) -> Available {
        let mut a = Available::empty();

        if self.is_recv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }

        a
    }

    pub fn accept(
        nic: &mut Iface,
        ip_header: etherparse::Ipv4HeaderSlice,
        tcp_header: etherparse::TcpHeaderSlice,
    ) -> Result<Option<Self>> {
        if !tcp_header.syn() {
            return Ok(None);
        }

        let iss = 0;

        let wnd = 1024;

        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
            },
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,
            },
            recv: RecvSequenceSpace {
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
            },
            ip_h: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpNumber::TCP,
                ip_header.destination(),
                ip_header.source(),
            )
            .expect("Failed to create IP header"),

            tcp_h: etherparse::TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss,
                wnd,
            ),
            incoming: Default::default(),
            unacked: Default::default(),
            closed: false,
            closed_at: None,
        };

        c.tcp_h.syn = true;

        c.tcp_h.ack = true;

        c.write(nic, c.send.nxt, 0)?;

        Ok(Some(c))
    }

    fn write(&mut self, nic: &Iface, seq: u32, mut limit: usize) -> Result<usize> {
        let mut buf = [0u8; 1500];

        self.tcp_h.sequence_number = seq;
        self.tcp_h.acknowledgment_number = self.recv.nxt;

        let mut offset = seq.wrapping_sub(self.send.una) as usize;

        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                offset = 0;
                limit = 0;
            }
        }

        let (mut h, mut t) = self.unacked.as_slices();

        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }

        let max_data = min(limit, h.len() + t.len());

        let size = min(
            buf.len(),
            self.tcp_h.header_len() + self.ip_h.header_len() + max_data,
        );

        self.ip_h
            .set_payload_len(size - self.ip_h.header_len())
            .unwrap();

        let buf_len = buf.len();

        let mut unwritten = &mut buf[..];

        self.ip_h.write(&mut unwritten)?;

        let ip_header_end = buf_len - unwritten.len();

        unwritten = &mut unwritten[self.tcp_h.header_len() as usize..];

        let tcp_header_end = buf_len - unwritten.len();

        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            let p1len = min(limit, h.len());
            written += unwritten.write(&h[..p1len])?;
            limit -= written;

            let p2len = min(limit, t.len());
            written += unwritten.write(&t[..p2len])?;
            written
        };

        let payload_ends_at = buf_len - unwritten.len();

        let payload = &buf[tcp_header_end..payload_ends_at];

        self.tcp_h.checksum = self
            .tcp_h
            .calc_checksum_ipv4(&self.ip_h, payload)
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_end..tcp_header_end];

        self.tcp_h.write(&mut tcp_header_buf)?;

        let mut next_seq = seq.wrapping_add(payload_bytes as u32);

        if self.tcp_h.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp_h.syn = false;
        }

        if self.tcp_h.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp_h.fin = false;
        }

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }

        self.timers.send_times.insert(seq, time::Instant::now());

        nic.send(&buf[..payload_ends_at])?;

        Ok(payload_bytes)
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        self.closed = true;
        match self.state {
            State::SynRcvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closing",
                ))
            }
        };
        Ok(())
    }

    pub(crate) fn on_tick(&mut self, nic: &mut Iface) -> Result<()> {
        if let State::FinWait2 | State::TimeWait = self.state {
            return Ok(());
        }

        let nunacked_data = self
            .closed_at
            .unwrap_or(self.send.nxt)
            .wrapping_sub(self.send.una);

        let nunsent_data = self.unacked.len() as u32 - nunacked_data;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            let resend = min(self.unacked.len() as u32, self.send.wnd as u32);

            if resend < self.send.wnd as u32 && self.closed {
                self.tcp_h.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }

            self.write(nic, self.send.una, resend as usize)?;
        } else {
            if nunsent_data == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as u32 - nunacked_data;

            if allowed == 0 {
                return Ok(());
            }

            let send = min(nunsent_data, allowed);

            if send < allowed && self.closed && self.closed_at.is_none() {
                self.tcp_h.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }

            self.write(nic, self.send.nxt, send as usize)?;
        }

        Ok(())
    }

    pub(crate) fn on_packet(
        &mut self,
        nic: &mut Iface,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> Result<Available> {
        let seqn = tcp_header.sequence_number();

        let mut slen = data.len() as u32;

        if tcp_header.fin() {
            slen += 1
        };

        if tcp_header.syn() {
            slen += 1
        };

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            eprintln!("NOT OKAY");
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        if !tcp_header.ack() {
            if tcp_header.syn() {
                // got SYN part of initial handshake
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }

            return Ok(self.availability());
        }

        let ackn = tcp_header.acknowledgment_number();

        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                self.state = State::Estab;
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                println!(
                    "ack for {} (last: {}); prune in {:?}",
                    ackn, self.send.una, self.unacked
                );
                if !self.unacked.is_empty() {
                    let data_start = if self.send.una == self.send.iss {
                        // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };

                    let acked_data_end =
                        min(ackn.wrapping_sub(data_start) as _, self.unacked.len());

                    self.unacked.drain(..acked_data_end);

                    self.timers.send_times.retain(|&seq, sent| {
                        if is_between_wrapped(self.send.una, seq, ackn) {
                            self.timers.srtt =
                                0.8 * self.timers.srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                            false
                        } else {
                            true
                        }
                    });
                }
                self.send.una = ackn;
            }
        }

        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed!
                    self.state = State::FinWait2;
                }
            }
        }

        if !data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;
                if unread_data_at > data.len() {
                    // we must have received a re-transmitted FIN that we have already seen
                    // nxt points to beyond the fin, but the fin is not in data!
                    assert_eq!(unread_data_at, data.len() + 1);
                    unread_data_at = 0;
                }
                self.incoming.extend(&data[unread_data_at..]);

                /*
                Once the TCP takes responsibility for the data it advances
                RCV.NXT over the data accepted, and adjusts RCV.WND as
                apporopriate to the current buffer availability.  The total of
                RCV.NXT and RCV.WND should not be reduced.
                 */
                self.recv.nxt = seqn.wrapping_add(data.len() as u32);

                // Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                // TODO: maybe just tick to piggyback ack on data?
                self.write(nic, self.send.nxt, 0)?;
            }
        }

        if tcp_header.fin() {
            match self.state {
                State::FinWait2 => {
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.availability())
    }
}

struct SendSequenceSpace {
    /// initial send sequence number
    iss: u32,
    /// sequence number of first byte to not be acknowledged
    una: u32,
    /// sequence number of next byte to send
    nxt: u32,
    /// the window size
    wnd: u16,
}

struct RecvSequenceSpace {
    /// The sequence number of the next byte to be recieved from the client
    nxt: u32,
    /// The client's window size
    wnd: u16,
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
