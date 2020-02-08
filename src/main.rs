
pub mod client;

use client::{
    Authentication,
    SocksClient,
    TargetAddr,
};

#[forbid(unsafe_code)]
use async_std::{
    net::{TcpStream, ToSocketAddrs},
    task,
    io::Result,
};

use futures::{task::Poll, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

async fn spawn_socks_client() -> Result<()> {
    let mut client = SocksClient::new(
        "127.0.0.1:1080",
        vec![Authentication::None],
    ).await?;

    let mut stream = client.connect(TargetAddr::Domain(String::from("www.baidu.com"), 80)).await.unwrap();
    let mut headers = vec![];
    headers.extend_from_slice("GET / HTTP/1.1\r\nHost: ".as_bytes());
    headers.extend_from_slice("www.baidu.com".as_bytes());
    headers
        .extend_from_slice("\r\nUser-Agent: fast-socks5/0.1.0\r\nAccept: */*\r\n\r\n".as_bytes());

    // flush headers
    stream
        .write_all(&headers)
        .await;
        println!("Reading body response...");
        let mut result = [0u8; 1024];
        // warning: read_to_end() method sometimes await forever when the web server
        // doesn't write EOF char (\r\n\r\n).
        // read() seems more appropriate
        stream
            .read(&mut result)
            .await;

        println!("Response: {}", String::from_utf8_lossy(&result));

    Ok(())
}

fn main() {
    task::block_on(spawn_socks_client());
}