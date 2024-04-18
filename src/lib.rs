mod tcp;
use etherparse::{ip_number::TCP, Ipv4HeaderSlice, TcpHeaderSlice};
use nix::poll::PollTimeout;
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::io::Result;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::{Arc, Condvar, Mutex};
use std::{
    io::{Read, Write},
    net::Ipv4Addr,
};
use tun_tap::Iface;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dest: (Ipv4Addr, u16),
}

#[derive(Default)]
struct InterfaceHandle {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    recv_var: Condvar,
}

#[derive(Default)]
struct ConnectionManager {
    terminate: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

pub struct Interface {
    ih: Option<Arc<InterfaceHandle>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;

        drop(self.ih.take());
    }
}

fn packet_loop(mut nic: Iface, ih: Arc<InterfaceHandle>) -> Result<()> {
    let mut buf = [0u8; 1504];

    loop {
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(nic.as_raw_fd()) };

        use nix::poll::PollFlags;

        let pfd = nix::poll::PollFd::new(borrowed_fd, PollFlags::POLLIN);

        let n = nix::poll::poll(&mut [pfd], PollTimeout::from(1u8))?;

        assert_ne!(n, -1);

        if n == 0 {
            let mut cmg = ih.manager.lock().unwrap();

            for connection in cmg.connections.values_mut() {
                connection.on_tick(&mut nic)?;
            }

            continue;
        }

        assert_eq!(n, 1);

        let nbytes = nic.recv(&mut buf)?;

        let ip_h = match Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(ip_header) => ip_header,
            Err(_) => {
                eprintln!("Non-IPV4 packet.");
                continue;
            }
        };

        let src = ip_h.source_addr();

        let dst = ip_h.destination_addr();

        if ip_h.protocol() != TCP {
            eprintln!("Non-TCP packet.");
            continue;
        }

        let ip_header_parserd = &buf[ip_h.slice().len()..nbytes];

        let tcp_h = match TcpHeaderSlice::from_slice(ip_header_parserd) {
            Ok(tcp_header) => tcp_header,
            Err(_) => {
                eprintln!("Mangled TCP packet.");
                continue;
            }
        };

        // First byte of TCP payload
        let datai = ip_h.slice().len() + tcp_h.slice().len();

        let mut cmg = ih.manager.lock().unwrap();

        let cm = &mut *cmg;

        let q = Quad {
            src: (src, tcp_h.source_port()),
            dest: (dst, tcp_h.destination_port()),
        };

        match cm.connections.get_mut(&q) {
            Some(connection) => {
                println!("Got packet from known quad {:?}", q);

                let a = connection
                    .on_packet(&mut nic, tcp_h, &buf[datai..nbytes])
                    .unwrap();

                if a.contains(tcp::Available::READ) {
                    ih.recv_var.notify_all();
                }

                if a.contains(tcp::Available::WRITE) {}
            }

            None => {
                println!("Got packet from unknown quad {:?}", q);

                let destination_port = &tcp_h.destination_port();
                use tcp::Connection;

                let nic = &mut nic;

                if let Some(pending) = cm.pending.get_mut(destination_port) {
                    if let Some(c) = Connection::accept(nic, ip_h, tcp_h)
                        .expect("Failed to accept incoming connection.")
                    {
                        cm.connections.insert(q, c);

                        pending.push_back(q);

                        drop(cmg);

                        ih.pending_var.notify_all();
                    }
                }
            }
        }
    }
}

impl Interface {
    pub async fn new() -> Result<Self> {
        let mode = tun_tap::Mode::Tun;

        let nic = tun_tap::Iface::without_packet_info("tun0", mode)?;

        let ih: Arc<InterfaceHandle> = Default::default();

        let _ = {
            let ih = ih.clone();
            let x = tokio::spawn(async { packet_loop(nic, ih) }).await?;
        };

        Ok(Interface { ih: Some(ih) })
    }

    pub fn bind(&mut self, port: u16) -> Result<TcpListener> {
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();

        match cm.pending.get(&port) {
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Port already bound",
                ));
            }

            None => {
                cm.pending.insert(port, VecDeque::new());
            }
        };

        drop(cm);

        Ok(TcpListener {
            port,
            ih: self.ih.as_mut().unwrap().clone(),
        })
    }
}

pub struct TcpListener {
    port: u16,
    ih: Arc<InterfaceHandle>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.ih.manager.lock().unwrap();

        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");

        for _quad in pending {
            unimplemented!();
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> Result<TcpStream> {
        let mut cm = self.ih.manager.lock().unwrap();

        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("Port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    quad,
                    ih: self.ih.clone(),
                });
            }

            cm = self.ih.pending_var.wait(cm).unwrap();
        }
    }
}

pub struct TcpStream {
    quad: Quad,
    ih: Arc<InterfaceHandle>,
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut cm = self.ih.manager.lock().unwrap();

        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Stream was terminated unexpectedly",
                )
            })?;

            if c.is_recv_closed() && c.incoming.is_empty() {
                return Ok(0);
            }

            if !c.incoming.is_empty() {
                let mut nread = 0;

                let (head, tail) = c.incoming.as_slices();

                let hread = std::cmp::min(buf.len(), head.len());

                buf[..hread].copy_from_slice(&head[..hread]);

                nread += hread;

                let tread = std::cmp::min(buf.len() - nread, tail.len());

                buf[hread..(hread + tread)].copy_from_slice(&tail[..tread]);

                nread += tread;

                drop(c.incoming.drain(..nread));

                return Ok(nread);
            }

            cm = self.ih.recv_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut cm = self.ih.manager.lock().unwrap();

        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.len() >= SENDQUEUE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Too many bytes buffered",
            ));
        }

        let nwrite = min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());

        c.unacked.extend(buf[..nwrite].iter());

        Ok(nwrite)
    }

    fn flush(&mut self) -> Result<()> {
        let mut cm = self.ih.manager.lock().unwrap();

        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Stream was terminated unexpectedly",
            ))
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, _how: Shutdown) -> Result<()> {
        let mut cm = self.ih.manager.lock().unwrap();

        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Stream was terminated unexpectedly",
            )
        })?;

        c.close()
    }
}
