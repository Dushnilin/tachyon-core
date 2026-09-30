//! An h2 server that only reports what it was asked for.
//!
//! The XHTTP tests run our client against an h2 server of our own making, which
//! is exactly the arrangement where a client and a server agree with each other
//! and neither agrees with Xray. So this one is deliberately not an XHTTP server:
//! it prints every request it receives and answers 200, so the same configuration
//! can be pointed at our client and at the reference's and the two transcripts
//! compared line by line.
//!
//!     cargo run -p core-runtime --example xhttp_dump_server -- <port>

use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = env::args()
        .nth(1)
        .unwrap_or_else(|| "19700".to_string())
        .parse()
        .expect("a port number");
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("xhttp-dump listening on 127.0.0.1:{port}");

    loop {
        let (socket, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut server = match h2::server::handshake(socket).await {
                Ok(server) => server,
                Err(e) => {
                    eprintln!("[{peer}] not h2c: {e}");
                    return;
                }
            };
            eprintln!("[{peer}] ---- connection");
            while let Some(request) = server.accept().await {
                let (request, mut respond) = match request {
                    Ok(pair) => pair,
                    Err(e) => {
                        eprintln!("[{peer}] stream error: {e}");
                        break;
                    }
                };
                let method = request.method().clone();
                let uri = request.uri().clone();
                println!("REQ {method} {uri}");
                for name in request.headers().keys() {
                    let value = request
                        .headers()
                        .get(name)
                        .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string())
                        .unwrap_or_default();
                    // a long padding value is noise; its length is the interesting part
                    let shown = if value.len() > 60 {
                        format!("{}…({} bytes)", &value[..40], value.len())
                    } else {
                        value
                    };
                    println!("    {name}: {shown}");
                }
                use std::io::Write;
                let _ = std::io::stdout().flush();

                let mut body = request.into_body();
                let mut uploaded = Vec::new();
                while let Some(chunk) = body.data().await {
                    let Ok(chunk) = chunk else { break };
                    let _ = body.flow_control().release_capacity(chunk.len());
                    uploaded.extend_from_slice(&chunk);
                }
                if !uploaded.is_empty() {
                    println!("    body: {} bytes: {}", uploaded.len(), hex(&uploaded));
                }

                let response = http::Response::builder().status(200).body(()).unwrap();
                match respond.send_response(response, false) {
                    Ok(mut send) => {
                        let _ =
                            send.send_data(bytes::Bytes::from_static(b"server-says-hello"), true);
                    }
                    Err(e) => eprintln!("[{peer}] send_response: {e}"),
                }
            }
        });
    }
}

fn hex(data: &[u8]) -> String {
    data.iter()
        .take(48)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
