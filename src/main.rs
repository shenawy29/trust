use std::io::{Read, Write};

use std::io::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let mut i = trust::Interface::new().await?;

    let mut l1 = i.bind(9000)?;

    tokio::spawn(async move {
        while let Ok(mut stream) = l1.accept() {
            println!("Got a connection!");

            stream.write(b"hello from rust-tcp!\n").unwrap();

            stream.shutdown(std::net::Shutdown::Write).unwrap();

            loop {
                let mut buf = [0; 512];

                let n = stream.read(&mut buf).unwrap();

                println!("read {}b of data", n);

                if n == 0 {
                    println!("no more data!");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        }
    });

    Ok(())
}
