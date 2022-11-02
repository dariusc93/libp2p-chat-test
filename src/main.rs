mod behaviour;
mod transport;

use behaviour::{ChatBehaviour, ChatBehaviourEvent};
use clap::Parser;
use crypto_seal::{key::PrivateKey, Package, ToOpenWithPublicKey, ToSealWithSharedKey};
use futures::{FutureExt, StreamExt};
use libp2p::{
    core::PublicKey,
    identify::{Event as IdentifyEvent, Info as IdentifyInfo},
    identity::Keypair,
    kad::{record::Key, GetProvidersOk, KademliaEvent, QueryId, QueryResult},
    mdns::MdnsEvent,
    multiaddr::Protocol,
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use rustyline_async::{Readline, ReadlineError, SharedWriter};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, hash::Hash, io::Write, str::FromStr, time::Duration};

const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

#[derive(Hash, PartialEq, Eq)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub address: Vec<Multiaddr>,
    pub public_key: crypto_seal::key::PublicKey,
}

#[derive(Debug, Parser)]
#[clap(name = "libp2p chat")]
struct CliOpt {
    #[clap(long)]
    listen_address: Option<Vec<Multiaddr>>,

    #[clap(long)]
    topic: String,

    #[clap(long)]
    use_relay: bool,
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
        true => {
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
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic".parse().unwrap())?;
        swarm.listen_on("/ip6/::/udp/0/quic".parse().unwrap())?;
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
    if opt.use_relay {
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

    let topic_key = Key::from(topic_hash(topic.as_bytes()));

    let mut query_registry = HashSet::new();

    query_registry.insert(
        swarm
            .behaviour_mut()
            .kademlia
            .start_providing(topic_key.clone())?,
    );

    futures::pin_mut!(stream);

    let mut peer_book: HashSet<PeerInfo> = HashSet::new();
    let mut find_peer = PeerId::random();
    let mut bootstrap_interval = tokio::time::interval(Duration::from_secs(120));
    let mut get_provider_interval = tokio::time::interval(Duration::from_millis(500));
    let mut peer_list: HashSet<PeerId> = HashSet::new();
    // let x = {
    //     let peers = swarm.behaviour().gossipsub.subscribed_peers(&topic);

    //     let peer_not_found = peers.iter().zip()

    // };
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
                            for recipient in peer_book.iter() {
                                writeln!(stdout, "Public Key: {}", recipient.public_key)?;
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
                            let id = swarm.behaviour_mut().kademlia.get_closest_peers(peer);
                            query_registry.insert(id);
                        }
                        Some("!id") => {
                            writeln!(stdout, "Public Key: {}", private.public_key()?)?;
                        }
                        _ => {
                            if !line.is_empty() {
                                let line = line.to_string();
                                let message = line.clone().seal(&private, peer_book.iter().map(|info| info.public_key.clone()).collect::<Vec<_>>())?;

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
            },
            event = swarm.select_next_some() => {
                match swarm_event(&mut stdout, &mut swarm, event, &mut peer_book, &mut peer_list, &mut query_registry, find_peer).await {
                    Ok(_) => {},
                    Err(e) => {
                        writeln!(stdout, "Error processing event: {}", e)?;
                    }
                }
            }
            _ = bootstrap_interval.tick() => {
                swarm.behaviour_mut().kademlia.bootstrap()?;
            },
            _ = get_provider_interval.tick() => {
                query_registry.insert(swarm.behaviour_mut().kademlia.get_providers(topic_key.clone()));
            },
        }
    }
    Ok(())
}

async fn swarm_event<S>(
    stdout: &mut SharedWriter,
    swarm: &mut Swarm<ChatBehaviour>,
    event: SwarmEvent<ChatBehaviourEvent, S>,
    peer_book: &mut HashSet<PeerInfo>,
    peer_list: &mut HashSet<PeerId>,
    query_registry: &mut HashSet<QueryId>,
    find_peer: PeerId,
) -> anyhow::Result<()> {
    match event {
        SwarmEvent::Behaviour(ChatBehaviourEvent::Rendezvous(_)) => {}
        SwarmEvent::Behaviour(ChatBehaviourEvent::RelayClient(_event)) => {
            // writeln!(stdout, "Relay Client Event: {:?}", event)?;
        }
        SwarmEvent::Behaviour(ChatBehaviourEvent::RelayServer(_event)) => {}
        SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(
            libp2p::gossipsub::GossipsubEvent::Unsubscribed { peer_id, .. },
        )) => {
            for peer in peer_book.iter() {
                if peer.peer_id == peer_id {
                    writeln!(stdout, "{} has left.", peer.public_key)?;
                    break;
                }
            }
        }
        SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(_)) => {}
        SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(event)) => match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _) in list {
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _) in list {
                    if let Some(mdns) = swarm.behaviour().mdns.as_ref() {
                        if !mdns.has_node(&peer) {
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                        }
                    }
                }
            }
        },
        SwarmEvent::Behaviour(ChatBehaviourEvent::Ping(_event)) => {}
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
                if agent_version == "libp2p-chat" {
                    if let PublicKey::Ed25519(pk) = public_key {
                        match crypto_seal::key::PublicKey::from_ed25519_bytes(&pk.encode()) {
                            Ok(pk) if !peer_book.iter().any(|peer| peer.public_key == pk) => {
                                writeln!(stdout, "> {} joined", pk)?;
                                peer_book.insert(PeerInfo {
                                    peer_id,
                                    public_key: pk,
                                    address: listen_addrs.clone(),
                                });
                            }
                            _ => {}
                        }
                    }
                }
                if protocols
                    .iter()
                    .any(|p| p.as_bytes() == libp2p::kad::protocol::DEFAULT_PROTO_NAME)
                {
                    for addr in &listen_addrs {
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());
                    }
                }

                if protocols
                    .iter()
                    .any(|p| p.as_bytes() == libp2p::autonat::DEFAULT_PROTOCOL_NAME)
                {
                    for addr in listen_addrs {
                        swarm
                            .behaviour_mut()
                            .autonat
                            .add_server(peer_id, Some(addr));
                    }
                }
            }
        }
        SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(KademliaEvent::OutboundQueryCompleted {
            id,
            result,
            ..
        })) => match result {
            QueryResult::GetClosestPeers(Ok(ok)) => {
                if query_registry.remove(&id) {
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
            }

            QueryResult::StartProviding(_) => {}
            QueryResult::GetProviders(Ok(GetProvidersOk { providers, .. })) => {
                if query_registry.remove(&id) {
                    for peer in providers {
                        if !peer_list.contains(&peer) {
                            if let Err(_e) = swarm.dial(peer) {
                                continue;
                            }
                            peer_list.insert(peer);
                        }
                    }
                }
            }
            _ => {}
        },
        SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(_)) => {}
        SwarmEvent::Behaviour(ChatBehaviourEvent::Autonat(_)) => {}
        SwarmEvent::Behaviour(ChatBehaviourEvent::Dcutr(_)) => {}
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
        SwarmEvent::Dialing(_) => {}
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
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(IdentifyEvent::Received { .. })) => {
                            recv = true;
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

    Ok(())
}

pub fn topic_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(b"libp2p-chat");
    hasher.finalize().to_vec()
}
