use std::{
    io::{Error, ErrorKind},
    net::Ipv4Addr,
};

use pnet::{
    datalink::{self, Channel, NetworkInterface},
    ipnetwork::IpNetwork,
    packet::{ethernet::EthernetPacket, Packet},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interface_name: &str = "enp8s0f1";

    let interfaces = datalink::interfaces();

    println!("The interface chosen: {}", interfaces.len());
    let found: NetworkInterface = match interfaces
        .iter()
        .filter(|ip_s| !ip_s.ips.is_empty()) // Removeinterfaces without IPs
        .find(|iface| iface.name == interface_name)
    {
        Some(iface) => iface.clone(),
        None => {
            return Err(Box::new(Error::new(
                ErrorKind::Other,
                "Interface not found",
            )))
        }
    };

    // Find the first interface with a non-local IP address
    let first_interface =
        match interfaces
            .iter()
            .filter(|ip_s| !ip_s.ips.is_empty())
            .find(|iface| {
                iface
                    .ips
                    .iter()
                    .filter(|ip| match ip {
                        IpNetwork::V4(ip) => ip.ip() != Ipv4Addr::new(127, 0, 0, 1),
                        IpNetwork::V6(_) => false,
                    })
                    .count()
                    > 0
            }) {
            Some(iface) => iface.clone(),
            None => {
                return Err(Box::new(Error::new(
                    ErrorKind::Other,
                    "Interface not found",
                )))
            }
        };

    println!("First interface: {}", first_interface.name);
    println!("Found interface: {}", found.name);

    // Channel to receive packets
    let (_tx, mut rx) = match datalink::channel(&found, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            return Err(Box::new(e));
        }
    };

    let mut count = 0;

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = packet.to_vec();
                count += 1;
                println!("Packet {count} length: {}", packet.len());
                analyze_packet(EthernetPacket::new(&packet), found.clone(), packet.len());
            }
            Err(err) => {
                println!("Packet reading error occurred: {err:?}");
                break;
            }
        }
    }

    Ok(())
}

fn analyze_packet(packet: Option<EthernetPacket>, found: NetworkInterface, packet_size: usize) {
    match packet {
        Some(packet) => {
            println!("\nTCP Packet:");
            println!("  Source Port: {:?}", packet.get_source());
            println!("  Destination Port: {:?}", packet.get_destination());
            println!(
                "    Destination Match: {:?}",
                packet.get_destination() == found.mac.unwrap()
            );
            println!("  Payload len: {}", packet.payload().len());
            println!("  Data Size: {}\n\n", packet_size - packet.payload().len());
        }
        None => {
            println!("NO PACKET FOUND");
        }
    }
}
