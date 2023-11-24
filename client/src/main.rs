use std::error::Error;
use std::io::{stdin, stdout, Write};
use std::net::TcpStream;

use shared::linecodec::{
    TcpStreamLineCodec, BEGIN_MESSAGE, INFORMATION_REQUEST, PUBLIC_KEY_REQUEST,
};
use shared::simple_hpke::{SimpleHpke, SimplePublicKey};
use shared::Serializable;

const SERVER_ADDRESS: &str = "127.0.0.1:8080";

fn retrieve_pub_key(conn: &mut TcpStreamLineCodec) -> Result<SimplePublicKey, Box<dyn Error>> {
    conn.write_bytes(PUBLIC_KEY_REQUEST.as_bytes())?;
    let res = conn.read_bytes()?;
    let key = SimplePublicKey::from_bytes(&res)?;
    Ok(key)
}

fn retrieve_information(conn: &mut TcpStreamLineCodec) -> Result<String, Box<dyn Error>> {
    conn.write_bytes(INFORMATION_REQUEST.as_bytes())?;
    let res = conn.read_string()?;
    Ok(res)
}

fn prompt_user(msg: &str) -> String {
    let mut s = String::new();
    println!("{msg}");
    let _ = stdout().flush();
    stdin()
        .read_line(&mut s)
        .expect("Please provide a valid string");
    if let Some('\n') = s.chars().next_back() {
        s.pop();
    }
    if let Some('\r') = s.chars().next_back() {
        s.pop();
    }
    s
}

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(SERVER_ADDRESS)?;

    // Build buffered connection
    let mut conn = TcpStreamLineCodec::from_stream(stream)?;

    println!("getting public key from server...");
    let public_key = retrieve_pub_key(&mut conn)?;

    println!("getting public information from server... \n");
    let information = retrieve_information(&mut conn)?;

    let message = prompt_user("Please type in the message you want to sent:");
    let associated = prompt_user("Please provide the associated data:");

    println!("enconding message...");
    let (encapped, cypher, tag) = SimpleHpke::encrypt(
        message.as_bytes(),
        associated.as_bytes(),
        &public_key.as_bytes(),
        information.as_bytes(),
    );

    println!("sending message...");
    conn.write_bundled_bytes(vec![
        BEGIN_MESSAGE.as_bytes(),
        &encapped.to_bytes(),
        &cypher,
        &tag.to_bytes(),
        associated.as_bytes(),
    ])?;

    println!("Message successfully sent!");

    Ok(())
}
