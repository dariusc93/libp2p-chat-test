#![allow(unused_imports)]
use std::sync::{atomic::AtomicBool, Arc};

use crypto_seal::key::PrivateKey;
use libp2p::gossipsub::{self, Behaviour as Gossipsub, MessageAuthenticity};
use libp2p::relay::client::Transport as ClientTransport;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub::Event as GossipsubEvent, swarm::behaviour::toggle::Toggle, PeerId, Swarm};

use libp2p::{
    self,
    autonat::{Behaviour as Autonat, Event as AutonatEvent},
    dcutr::{Behaviour as DcutrBehaviour, Event as DcutrEvent},
    identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent},
    kad::{store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent},
    mdns::{tokio::Behaviour as Mdns, Config as MdnsConfig, Event as MdnsEvent},
    ping::{Behaviour as Ping, Event as PingEvent},
    relay::client::{self, Behaviour as RelayClient, Event as RelayClientEvent},
    relay::{Behaviour as RelayServer, Event as RelayServerEvent},
    rendezvous::{
        self,
        client::{Behaviour as Rendezvous, Event as RendezvousEvent},
    },
};

use libp2p_helper::gossipsub::GossipsubStream;
use tokio::io::{self, AsyncBufReadExt};

use crate::{keypair_from_privkey, transport};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ChatBehaviourEvent", event_process = false)]
pub struct ChatBehaviour {
    pub relay_client: Toggle<RelayClient>,
    pub relay_server: Toggle<RelayServer>,
    pub dcutr: Toggle<DcutrBehaviour>,
    pub autonat: Autonat,
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
    pub ping: Ping,
    pub rendezvous: Rendezvous,
    pub gossipsub: GossipsubStream,
    pub mdns: Toggle<Mdns>,
}

pub enum ChatBehaviourEvent {
    RelayClient(RelayClientEvent),
    RelayServer(RelayServerEvent),
    Dcutr(DcutrEvent),
    Autonat(AutonatEvent),
    Kad(KademliaEvent),
    Identify(IdentifyEvent),
    Ping(PingEvent),
    Gossipsub(GossipsubEvent),
    Rendezvous(RendezvousEvent),
    Mdns(MdnsEvent),
}

impl From<RelayClientEvent> for ChatBehaviourEvent {
    fn from(event: RelayClientEvent) -> Self {
        ChatBehaviourEvent::RelayClient(event)
    }
}

impl From<RelayServerEvent> for ChatBehaviourEvent {
    fn from(event: RelayServerEvent) -> Self {
        ChatBehaviourEvent::RelayServer(event)
    }
}

impl From<DcutrEvent> for ChatBehaviourEvent {
    fn from(event: DcutrEvent) -> Self {
        ChatBehaviourEvent::Dcutr(event)
    }
}

impl From<AutonatEvent> for ChatBehaviourEvent {
    fn from(event: AutonatEvent) -> Self {
        ChatBehaviourEvent::Autonat(event)
    }
}

impl From<KademliaEvent> for ChatBehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        ChatBehaviourEvent::Kad(event)
    }
}

impl From<IdentifyEvent> for ChatBehaviourEvent {
    fn from(event: IdentifyEvent) -> Self {
        ChatBehaviourEvent::Identify(event)
    }
}

impl From<MdnsEvent> for ChatBehaviourEvent {
    fn from(event: MdnsEvent) -> Self {
        ChatBehaviourEvent::Mdns(event)
    }
}

impl From<GossipsubEvent> for ChatBehaviourEvent {
    fn from(event: GossipsubEvent) -> Self {
        ChatBehaviourEvent::Gossipsub(event)
    }
}

impl From<PingEvent> for ChatBehaviourEvent {
    fn from(event: PingEvent) -> Self {
        ChatBehaviourEvent::Ping(event)
    }
}

impl From<RendezvousEvent> for ChatBehaviourEvent {
    fn from(event: RendezvousEvent) -> Self {
        ChatBehaviourEvent::Rendezvous(event)
    }
}

impl ChatBehaviour {
    pub async fn create_behaviour(private_key: &PrivateKey) -> anyhow::Result<Self> {
        let keypair = keypair_from_privkey(private_key)?;
        let peer_id = keypair.public().to_peer_id();

        let mdns = Some(Mdns::new(MdnsConfig::default(), peer_id)?).into();
        let autonat = Autonat::new(peer_id, Default::default());
        let ping = Ping::default();
        let identify = Identify::new(
            IdentifyConfig::new("/ipfs/0.1.0".into(), keypair.public())
                .with_agent_version("libp2p-chat".into()),
        );
        let store = MemoryStore::new(peer_id);

        let kad_config = KademliaConfig::default();
        let kademlia = Kademlia::with_config(peer_id, store, kad_config);
        let gconfig = gossipsub::ConfigBuilder::default()
            .support_floodsub()
            .build()
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let goss = Gossipsub::new(MessageAuthenticity::Signed(keypair.clone()), gconfig)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let gossipsub = GossipsubStream::from(goss);
        let rendezvous = Rendezvous::new(keypair);
        Ok(Self {
            mdns,
            relay_client: None.into(),
            relay_server: None.into(),
            dcutr: None.into(),
            autonat,
            kademlia,
            identify,
            ping,
            gossipsub,
            rendezvous,
        })
    }

    pub fn enable_relay(&mut self, peer_id: PeerId) -> ClientTransport {
        let dcutr = Some(DcutrBehaviour::new(peer_id)).into();
        let (transport, client) = client::new(peer_id);
        self.relay_client = Some(client).into();
        // Use for servers outside of the nat
        // self.relay_server = Some(RelayServer::new(peer_id, Default::default())).into();
        self.dcutr = dcutr;
        transport
    }

    pub fn create_swarm(
        self,
        private_key: &PrivateKey,
        relay_transport: Option<ClientTransport>,
    ) -> anyhow::Result<Swarm<Self>> {
        let keypair = keypair_from_privkey(private_key)?;
        let peerid = keypair.public().to_peer_id();
        let transport = transport::build_transport(keypair, relay_transport)?;

        let swarm = libp2p::swarm::SwarmBuilder::with_tokio_executor(transport, self, peerid)
            .dial_concurrency_factor(10_u8.try_into().unwrap())
            .build();
        Ok(swarm)
    }
}
