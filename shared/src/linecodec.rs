use std::{
    error::Error,
    fmt::Debug,
    io::{self, Read, Write},
    net::TcpStream,
};

use byteorder::{ByteOrder, NetworkEndian};

pub const PUBLIC_KEY_REQUEST: &str = "public_key";
pub const INFORMATION_REQUEST: &str = "information request";
pub const BEGIN_MESSAGE: &str = "begin message";

#[derive(Debug)]
pub struct LineCodec<Sink, Source>
where
    Sink: Write + Debug,
    Source: Read + Debug,
{
    writer: io::BufWriter<Sink>,
    reader: io::BufReader<Source>,
}

impl<Sink, Source> LineCodec<Sink, Source>
where
    Sink: Write + Debug,
    Source: Read + Debug,
{
    pub fn new(source: Source, sink: Sink) -> io::Result<LineCodec<Sink, Source>> {
        let writer = io::BufWriter::new(sink);
        let reader = io::BufReader::new(source);
        Ok(LineCodec { reader, writer })
    }

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

    pub fn write_bundled_bytes(&mut self, bundle: Vec<&[u8]>) -> io::Result<()> {
        for it in bundle {
            self.write_bytes(it)?
        }
        Ok(())
    }

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

    pub fn read_string(&mut self) -> Result<String, Box<dyn Error>> {
        let buf = self.read_bytes()?;
        let str = String::from_utf8(buf)?;
        Ok(str)
    }
}

pub type TcpStreamLineCodec = LineCodec<TcpStream, TcpStream>;

impl LineCodec<TcpStream, TcpStream> {
    pub fn from_stream(stream: TcpStream) -> io::Result<LineCodec<TcpStream, TcpStream>> {
        LineCodec::new(stream.try_clone()?, stream)
    }
}
