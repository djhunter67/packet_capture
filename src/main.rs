mod models;
use std::{
    io::{Error, ErrorKind},
    net::Ipv4Addr,
};

use models::helpers::Pool;
use pnet::{
    datalink::{self, Channel, NetworkInterface},
    ipnetwork::IpNetwork,
    packet::{ethernet::EthernetPacket, Packet},
};
use postgres::{Client, NoTls};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_pool = Pool::new("10.20.30.23", "packets", "djhunter67", "PNF27156");

    println!("\n\n\tInitializing the DB tables\n\n\t");
    match db_pool.init_db() {
        Ok(_) => println!("DB tables initialized"),
        Err(e) => println!("Error initializing DB tables: {:?}", e),
    };

    let interface_name: &str = "enp8s0f1";

    println!("Retreiving all interfaces");
    let interfaces = datalink::interfaces();

    println!("The interface chosen: {}", interfaces.len());
    let found: NetworkInterface = match interfaces
        .iter()
        .filter(|ip_s| !ip_s.ips.is_empty()) // Removeinterfaces without IPs
        .find(|iface| iface.name == interface_name)
    {
        Some(iface) => iface.clone(),
        None => return Err(anyhow::Error::msg("Interface not found")),
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
            None => return Err(anyhow::Error::msg("Interface not found")),
        };

    println!("First interface: {}", first_interface.name);
    println!("Found interface: {}", found.name);

    // Channel to receive packets
    let (_tx, mut rx) = match datalink::channel(&first_interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "An error occurred when creating the datalink channel: {:?}",
                    e
                ),
            )
            .into())
        }
    };

    let mut count = 0;

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = packet.to_vec();
                count += 1;
                println!("Packet {count} length: {}", packet.len());
                analyze_packet(EthernetPacket::new(&packet), found.clone(), &packet);
                save_packet(
                    EthernetPacket::new(&packet),
                    found.clone(),
                    &packet,
                    &db_pool,
                )
                .await;
                if count >= 1500 {
                    // Stop capture
                    break;
                }
            }
            Err(err) => {
                println!("Packet reading error occurred: {err:?}");
                break;
            }
        }
    }

    println!("\n\n\tCAPTURE COMPLETE\n\n");

    Ok(())
}

fn analyze_packet(packet: Option<EthernetPacket>, found: NetworkInterface, raw_packet: &[u8]) {
    match packet {
        Some(packet) => {
            println!("\nTCP Packet:");
            println!("  Source MAC: {:?}", packet.get_source());
            println!("  Destination MAC: {:?}", packet.get_destination());
            println!(
                "    Destination is Host?: {:?}",
                packet.get_destination() == found.mac.unwrap()
            );
            println!(
                "  Source Port: {}",
                std::str::from_utf8(&[packet.payload()[0]])
                    .unwrap_or("Invalid UTF-8")
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation())
                    .collect::<String>()
            );
            println!(
                "  Destination Port: {}",
                std::str::from_utf8(&[packet.payload()[1]])
                    .unwrap_or("Invalid UTF-8")
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation())
                    .collect::<String>()
            );
            // for pyload in packet.payload().chunks(1) {
            //     println!(
            //         "  Payload: {}",
            //         std::str::from_utf8(pyload)
            //             .unwrap_or("Invalid UTF-8")
            //             .chars()
            //             .filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation())
            //             .collect::<String>()
            //     );
            // }
            println!(
                "  Data Size: {}\n\n",
                raw_packet.len() - packet.payload().len()
            );
        }
        None => {
            println!("NO PACKET FOUND");
        }
    }
}

async fn save_packet(
    packet: Option<EthernetPacket<'_>>,
    found: NetworkInterface,
    raw_packet: &[u8],
    client: &Pool,
) {
    match packet {
        Some(packet) => {
            let source_mac = packet.get_source().to_string();
            let destination_mac = packet.get_destination().to_string();
            let source_port = std::str::from_utf8(&[packet.payload()[0]])
                .unwrap_or("Invalid UTF-8")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation())
                .collect::<String>();
            let destination_port = std::str::from_utf8(&[packet.payload()[1]])
                .unwrap_or("Invalid UTF-8")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation())
                .collect::<String>();
            let data_size = raw_packet.len() - packet.payload().len();

            let query = format!(
		"INSERT INTO interface (interface, source_mac, destination_mac, source_port, destination_port, data_size) VALUES ('{}', '{}', '{}', '{}', '{}', {});",
		found.description, source_mac, destination_mac, source_port, destination_port, data_size
	    );

            let mut client = Client::connect(&client.connection_str, NoTls).unwrap();

            match client.batch_execute(&query) {
                Ok(_) => {
                    println!("Packet saved to database");
                }
                Err(e) => {
                    println!("Error saving packet to database: {:?}", e);
                }
            }
        }
        None => {
            println!("NO PACKET FOUND");
        }
    }
}
