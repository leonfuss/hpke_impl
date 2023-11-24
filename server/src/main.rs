use std::error::Error;
use std::net::{TcpListener, TcpStream};

use shared::linecodec::INFORMATION_REQUEST;
use shared::linecodec::PUBLIC_KEY_REQUEST;
use shared::linecodec::{TcpStreamLineCodec, BEGIN_MESSAGE};
use shared::simple_hpke::SimpleHpke;

fn handle_client(stream: TcpStream, information: &str) -> Result<(), Box<dyn Error>> {
    let mut conn = TcpStreamLineCodec::from_stream(stream)?;

    let (private_key, public_key) = SimpleHpke::generate_key_pair();

    // allow key and information request in any order. We leave the loop, once Message transfer is initiated.
    loop {
        let res = {
            let bytes = conn.read_bytes()?;
            String::from_utf8(bytes)?
        };

        // providing public information
        match res.as_str() {
            INFORMATION_REQUEST => conn.write_bytes(information.as_bytes())?,
            PUBLIC_KEY_REQUEST => conn.write_bytes(&public_key.as_bytes())?,
            BEGIN_MESSAGE => break,
            e => return Err(format!("Message out of protocal range: {e}").into()),
        }
    }

    // reading all encrypted message details from stream
    let encaped = conn.read_bytes().expect("Failed to retrieve encapped key");

    let cypher = conn
        .read_bytes()
        .expect("Failed to retreive enconded message");
    let tag = conn.read_bytes().expect("Failed to retreive tag");
    let associated = conn.read_bytes().expect("Failed to read associated data");

    // decrypting message
    let bytes = SimpleHpke::decrypt(
        &private_key.as_bytes(),
        &encaped,
        &cypher,
        &associated,
        &tag,
        information.as_bytes(),
    );

    let message = String::from_utf8(bytes)?;
    let associated = String::from_utf8(associated)?;

    println!("Message: {message}");
    println!("Associated Data: {associated} \n");
    println!("Waiting for next connection...");
    Ok(())
}
fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to address");
    println!("Server listening on 127.0.0.1:8080 \n");

    for (idx, stream) in listener.incoming().enumerate() {
        let information = format!("Session: {idx}");
        match stream {
            Ok(stream) => {
                // spawn new thread for any incoming connection
                std::thread::spawn(move || handle_client(stream, &information).unwrap());
            }
            Err(e) => {
                eprintln!("Failed to establish connection: {}", e);
            }
        }
    }
}
