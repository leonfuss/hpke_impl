use std::{
    error::Error,
    fmt::Debug,
    io::{self, Read, Write},
    net::TcpStream,
};

use byteorder::{ByteOrder, NetworkEndian};

// simple protocol primitives
pub const PUBLIC_KEY_REQUEST: &str = "public_key";
pub const INFORMATION_REQUEST: &str = "information request";
pub const BEGIN_MESSAGE: &str = "begin message";

// Wraps a source and sink in a single interface to allow to simple message
// transfer without worrying to much about the implementation of the sink and
// source
#[derive(Debug)]
pub struct Codec<Sink, Source>
where
    Sink: Write + Debug,
    Source: Read + Debug,
{
    writer: io::BufWriter<Sink>,
    reader: io::BufReader<Source>,
}

impl<Sink, Source> Codec<Sink, Source>
where
    Sink: Write + Debug,
    Source: Read + Debug,
{
    // Create a new codec from source and sink
    pub fn new(source: Source, sink: Sink) -> io::Result<Codec<Sink, Source>> {
        let writer = io::BufWriter::new(sink);
        let reader = io::BufReader::new(source);
        Ok(Codec { reader, writer })
    }

    // Write provided bytes to sink and flush the sink.
    // The message length is prepended to allow for easy retrieval in stream
    // like environments (eg. Network)
    pub fn write_bytes(&mut self, msg: &[u8]) -> io::Result<()> {
        // write length to sink first
        let mut len = [0u8; 8];
        NetworkEndian::write_u64(&mut len, msg.len() as u64);
        self.writer.write_all(&len)?;

        // write actual data
        self.writer.write_all(msg)?;
        self.writer.flush()?;
        Ok(())
    }

    // calls write_bytes for every entry
    pub fn write_bundled_bytes(&mut self, bundle: Vec<&[u8]>) -> io::Result<()> {
        for it in bundle {
            self.write_bytes(it)?
        }
        Ok(())
    }

    // Retrieve bytes from the source in a blocking manner.
    pub fn read_bytes(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        // retrieve data length
        let mut num = [0u8; 8];
        self.reader.read_exact(&mut num)?;
        let count = NetworkEndian::read_u64(&num);

        // read data
        let mut buf = vec![0u8; count as usize];
        self.reader.read_exact(&mut buf)?;

        Ok(buf)
    }

    // Retrieve bytes from source and try to convert them in UTF-8 string. This
    // function will return an error if the received data is not a valid UTF-8
    // string.
    pub fn read_string(&mut self) -> Result<String, Box<dyn Error>> {
        let buf = self.read_bytes()?;
        let str = String::from_utf8(buf)?;
        Ok(str)
    }
}

pub type TcpStreamCodec = Codec<TcpStream, TcpStream>;

impl Codec<TcpStream, TcpStream> {
    // Construct Codec using the same TCP-stream for source and sink.
    pub fn from_stream(stream: TcpStream) -> io::Result<Codec<TcpStream, TcpStream>> {
        Codec::new(stream.try_clone()?, stream)
    }
}
