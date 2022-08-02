mod behaviour;
mod transport;

use behaviour::{ChatBehaviour, ChatBehaviourEvent};
use clap::Parser;
use crypto_seal::{key::PrivateKey, Package, ToOpenWithPublicKey, ToSealWithSharedKey};
use futures::{FutureExt, StreamExt};
use libp2p::{
    core::PublicKey,
    identify::{IdentifyEvent, IdentifyInfo},
    identity::Keypair,
    mdns::MdnsEvent,
    multiaddr::Protocol,
    swarm::{SwarmEvent, AddressScore},
    Multiaddr, PeerId, Swarm, kad::{QueryResult, KademliaEvent},
};
use rustyline_async::{Readline, ReadlineError, SharedWriter};
use std::{io::Write, str::FromStr};

const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

#[derive(Debug, Parser)]
#[clap(name = "libp2p chat")]
struct CliOpt {
    #[clap(long)]
    listen_address: Option<Vec<Multiaddr>>,

    #[clap(long)]
    topic: String,

    #[clap(long)]
    use_relay: Option<bool>,
}

fn new_keypair() -> anyhow::Result<(PrivateKey, Keypair)> {
    let private_key = PrivateKey::new();
    let mut bytes = private_key.to_bytes();
    let kp = Keypair::Ed25519(libp2p::identity::ed25519::Keypair::decode(&mut bytes)?);
    Ok((private_key, kp))
}

pub fn keypair_from_privkey(privkey: &PrivateKey) -> anyhow::Result<Keypair> {
    let mut bytes = privkey.to_bytes();
    let kp = Keypair::Ed25519(libp2p::identity::ed25519::Keypair::decode(&mut bytes)?);
    Ok(kp)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = CliOpt::parse();

    let (private, kp) = new_keypair()?;
    let peer = kp.public().to_peer_id();
    let mut behaviour = ChatBehaviour::create_behaviour(&private).await?;

    let relay_transport = match opt.use_relay {
        Some(true) => {
            let transport = behaviour.enable_relay(peer);
            Some(transport)
        }
        _ => None,
    };

    let mut swarm = behaviour.create_swarm(&private, relay_transport)?;
    if let Some(addrs) = opt.listen_address {
        for addr in addrs {
            swarm.listen_on(addr)?;
        }
    } else {
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())?;
        swarm.listen_on("/ip6/::/tcp/0".parse().unwrap())?;
    }

    let (mut rl, mut stdout) = Readline::new(format!("{}  :> ", peer))?;
    
    let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(2)).fuse();
    // Used to begin listening on addresses
    loop {
            futures::select! {
                event = swarm.next() => {
                    if let SwarmEvent::NewListenAddr { address, .. } = event.unwrap() {
                        writeln!(stdout, "> Listening on {}", address)?;
                    }
                }
                _ = delay => {
                    break;
                }
            }
    }
    

    let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;
    if let Some(true) = opt.use_relay {
        //Note that the loop is not needed but is used for testing multiple relay connections
        relay_check(
            &mut stdout,
            &mut swarm,
            BOOTNODES
                .iter()
                .map(|node| {
                    bootaddr
                        .clone()
                        .with(Protocol::P2p(PeerId::from_str(node).unwrap().into()))
                })
                .collect(),
        )
        .await?;
    }

    for peer in &BOOTNODES {
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&PeerId::from_str(peer)?, bootaddr.clone());
    }

    swarm.behaviour_mut().kademlia.bootstrap()?;

    let topic = opt.topic;

    let stream = swarm.behaviour_mut().gossipsub.subscribe(topic.clone())?;

    futures::pin_mut!(stream);

    let mut recipients: Vec<crypto_seal::key::PublicKey> = vec![];
    let mut find_peer = PeerId::random();
    loop {
        tokio::select! {
            message = stream.next() => {
                if let Some(message) = message {
                    if let Ok(pkg) = Package::<String>::from_slice(&message.data) {
                        if let Ok(msg) = pkg.open(&private) {
                            writeln!(stdout, "{} -- {}", message.source.unwrap(), msg)?;
                        }
                    }
                }
            }
            line = rl.readline().fuse() => match line {
                Ok(line) => {
                    let mut command = line.trim().split(' ');
                    match command.next() {
                        Some("!list") => {
                            for recipient in recipients.iter() {
                                writeln!(stdout, "Public Key: {}", bs58::encode(recipient.encode()).into_string())?;
                            }
                        },
                        Some("!dial-addr") => {
                            let addr = match command.next() {
                                Some(addr) => match Multiaddr::from_str(addr) {
                                    Ok(addr) => addr,
                                    Err(e) => {
                                        writeln!(stdout, "Error parsing multiaddr: {e}")?;
                                        continue
                                    }
                                },
                                None => {
                                    writeln!(stdout, "!dial-addr <address>")?;
                                    continue
                                }
                            };
                            if let Err(e) = swarm.dial(addr) {
                                writeln!(stdout, "Error dialing address: {e}")?;
                                continue
                            }
                        }
                        Some("!dial-peer") => {
                            let peer = match command.next() {
                                Some(peer) => match PeerId::from_str(peer) {
                                    Ok(peer) => peer,
                                    Err(e) => {
                                        writeln!(stdout, "Error parsing peerid: {e}")?;
                                        continue
                                    }
                                },
                                None => {
                                    writeln!(stdout, "!dial-peer <peer>")?;
                                    continue
                                }
                            };
                            if let Err(e) = swarm.dial(peer) {
                                writeln!(stdout, "Error dialing peer: {e}")?;
                                continue
                            }
                        }
                        Some("!find-peer") => {
                            let peer = match command.next() {
                                Some(peer) => match PeerId::from_str(peer) {
                                    Ok(peer) => peer,
                                    Err(e) => {
                                        writeln!(stdout, "Error parsing peerid: {e}")?;
                                        continue
                                    }
                                },
                                None => {
                                    writeln!(stdout, "!find-peer <peer>")?;
                                    continue
                                }
                            };
                            find_peer = peer;
                            writeln!(stdout, "Locating Peer {}", find_peer)?;
                            swarm.behaviour_mut().kademlia.get_closest_peers(peer);
                        }
                        Some("!id") => {
                            writeln!(stdout, "Public Key: {}", bs58::encode(private.public_key()?.encode()).into_string())?;
                        }
                        _ => {
                            if !line.is_empty() {
                                let line = line.to_string();
                                let message = line.clone().seal(&private, recipients.clone())?;

                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), message.to_vec()?) {
                                    writeln!(stdout, "Error sending message: {}", e)?;
                                    continue
                                }
                                writeln!(stdout, "{} -- {}", peer, line)?;
                            } else {
                                writeln!(stdout)?;
                            }
                       }
                    }
                },
                Err(ReadlineError::Interrupted) => {
                    writeln!(stdout, "")?;
                    break
                },
                Err(ReadlineError::Eof) => {
                    writeln!(stdout, "")?;
                    break
                },
                Err(e) => {
                    writeln!(stdout, "Error: {}", e)?;
                    continue
                }
            },// 
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(ChatBehaviourEvent::Rendezvous(_)) => {},
                    SwarmEvent::Behaviour(ChatBehaviourEvent::RelayClient(_event)) => {
                        // writeln!(stdout, "Relay Client Event: {:?}", event)?;
                    }
                    SwarmEvent::Behaviour(ChatBehaviourEvent::RelayServer(_event)) => { }
                    SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(_)) => {},
                    SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(event)) => match event {
                        MdnsEvent::Discovered(list) => {
                            for (peer, _) in list {
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                            }
                        }
                        MdnsEvent::Expired(list) => {
                            for (peer, _) in list {
                                if !swarm.behaviour().mdns.has_node(&peer) {
                                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                                }
                            }
                        }
                    },
                    SwarmEvent::Behaviour(ChatBehaviourEvent::Ping(_)) => {}
                    SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(event)) => {
                        if let IdentifyEvent::Received {
                            peer_id,
                            info:
                                IdentifyInfo {
                                    listen_addrs,
                                    protocols,
                                    public_key,
                                    agent_version,
                                    ..
                                },
                        } = event
                        {
                            //TODO: Use Rendezvous for discovery of peers under the same namespace
                            if agent_version == "libp2p-chat" {
                                if let PublicKey::Ed25519(pk) = public_key {
                                    match crypto_seal::key::PublicKey::from_ed25519_bytes(&pk.encode()) {
                                        Ok(pk) if !recipients.contains(&pk) => recipients.push(pk),
                                        _ => continue
                                    }
                                }
                            }
                            if protocols
                                .iter()
                                .any(|p| p.as_bytes() == libp2p::kad::protocol::DEFAULT_PROTO_NAME)
                            {
                                for addr in &listen_addrs {
                                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(event)) => {
                        match event {
                            KademliaEvent::OutboundQueryCompleted { result, .. } => match result {
                                QueryResult::GetClosestPeers(Ok(ok)) => {
                                    let mut found = false;
                                    for peer in ok.peers {
                                        if peer == find_peer {
                                            writeln!(stdout, "> {find_peer} found")?;
                                            found = true;
                                            break;
                                        }
                                    }
                                    if !found {
                                        writeln!(stdout, "> {find_peer} cannot be found")?;
                                    }
                                }
                                _ => {}
                            },
                            _ => {}
                        }
                    }
                    SwarmEvent::Behaviour(ChatBehaviourEvent::Autonat(_)) => {}
                    SwarmEvent::Behaviour(ChatBehaviourEvent::Dcutr(_)) => {},
                    SwarmEvent::ConnectionEstablished { .. } => {}
                    SwarmEvent::ConnectionClosed { .. } => {}
                    SwarmEvent::IncomingConnection { .. } => {}
                    SwarmEvent::IncomingConnectionError { .. } => {}
                    SwarmEvent::OutgoingConnectionError { .. } => {}
                    SwarmEvent::BannedPeer { .. } => {}
                    SwarmEvent::NewListenAddr { .. } => {}
                    SwarmEvent::ExpiredListenAddr { .. } => {}
                    SwarmEvent::ListenerClosed { .. } => {}
                    SwarmEvent::ListenerError { .. } => {}
                    SwarmEvent::Dialing( _ ) => {}
                }
            }
        }
    }
    Ok(())
}

async fn relay_check(
    stdout: &mut SharedWriter,
    swarm: &mut Swarm<ChatBehaviour>,
    relay_addrs: Vec<Multiaddr>,
) -> anyhow::Result<()> {
    for relay_addr in relay_addrs {
        swarm.dial(relay_addr.clone())?;

        let mut sent = false;
        let mut recv = false;
        // We check to determine the relay has responded with our address and reservation. If fails to respond within 20 seconds to timeout and error
        let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(20)).fuse();
        
        loop {
            futures::select! {
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Ping(_)) => {},
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(IdentifyEvent::Sent { .. })) => {
                            sent = true;
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(IdentifyEvent::Received {
                            info: IdentifyInfo { observed_addr, .. }, ..
                        })) => {
                            recv = true;
                            swarm.add_external_address(observed_addr, AddressScore::Infinite);
                        },
                        _ => continue
                    }
                }
                _ = delay => {
                    break;
                }
            }
            if sent && recv {
                break;
            }
        }

        if !sent || !recv {
            // Either we were unable to send or receive the event from the relay
            writeln!(stdout, "Unable to connect to relay {}", relay_addr)?;
            continue;
        }
        let relay_listener = relay_addr.with(Protocol::P2pCircuit);
        swarm.listen_on(relay_listener.clone())?;
        writeln!(stdout, "> Listening on relay {}", relay_listener)?;
    }

    writeln!(stdout, "> Listening on /p2p-circuit")?;
    Ok(())
}
