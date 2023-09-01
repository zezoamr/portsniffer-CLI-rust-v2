use bpaf::Bpaf;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Sender};
use tokio::net::TcpStream;
use tokio::task;

const MAX: u16 = 65535;
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
pub struct Arguments {
    // Address argument.  Accepts -a and --address and an IpAddr type. Falls back to the above constant.
    #[bpaf(long, short, argument("Address"), fallback(IPFALLBACK))]
    /// The address that you want to sniff.  Must be a valid ipv4 address.  Falls back to 127.0.0.1
    pub address: IpAddr,
    #[bpaf(
        long("start"),
        short('s'),
        guard(start_port_guard, "Must be greater than 0"),
        fallback(1u16)
    )]
    /// The start port for the sniffer. (must be greater than 0)
    pub start_port: u16,
    #[bpaf(
        long("end"),
        short('e'),
        guard(end_port_guard, "Must be less than or equal to 65535"),
        fallback(MAX)
    )]
    /// The end port for the sniffer. (must be less than or equal to 65535)
    pub end_port: u16,
}

fn end_greater_than_start_guard(input: &Arguments) -> bool {
    input.end_port > input.start_port
}

fn start_port_guard(input: &u16) -> bool {
    *input > 0
}

fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}

#[tokio::main]
async fn main() {
    //println!("{:?}", args);
    let opts = arguments().run();
    println!("{:?}", opts);
}
// ex to run: cargo run -- -s  1000 -e 1100 -a 192.168.1.1