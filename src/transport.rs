use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::timeout::TransportTimeout;
use libp2p::core::transport::upgrade::Version;
use libp2p::core::transport::{Boxed, OrTransport};
use libp2p::core::upgrade::SelectUpgrade;
use libp2p::dns::TokioDnsConfig;
use libp2p::identity;
use libp2p::mplex::MplexConfig;
use libp2p::noise::{self, NoiseConfig};
use libp2p::relay::v2::client::transport::ClientTransport;
use libp2p::tcp::{Config as GenTcpConfig, tokio::Transport as TokioTcpTransport};
use libp2p::yamux::{WindowUpdateMode, YamuxConfig};
use libp2p::{PeerId, Transport};
use std::io::{self, Error, ErrorKind};
use std::time::Duration;

pub fn build_transport(
    keypair: identity::Keypair,
    relay: Option<ClientTransport>,
) -> io::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let xx_keypair = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .unwrap();
    let noise_config = NoiseConfig::xx(xx_keypair).into_authenticated();

    let yamux_config = {
        let mut config = YamuxConfig::default();
        config.set_max_buffer_size(16 * 1024 * 1024);
        config.set_receive_window_size(16 * 1024 * 1024);
        config.set_window_update_mode(WindowUpdateMode::on_receive());
        config
    };

    let multiplex_upgrade = SelectUpgrade::new(yamux_config, MplexConfig::new());

    let tcp_transport = TokioTcpTransport::new(GenTcpConfig::default().nodelay(true).port_reuse(true));

    let transport_timeout = TransportTimeout::new(tcp_transport, Duration::from_secs(30));
    let transport = TokioDnsConfig::system(transport_timeout)?;

    let transport = match relay {
        Some(relay) => {
            let transport = OrTransport::new(relay, transport);
            transport
                .upgrade(Version::V1)
                .authenticate(noise_config)
                .multiplex(multiplex_upgrade)
                .timeout(Duration::from_secs(20))
                .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
                .map_err(|err| Error::new(ErrorKind::Other, err))
                .boxed()
        }
        None => transport
            .upgrade(Version::V1)
            .authenticate(noise_config)
            .multiplex(multiplex_upgrade)
            .timeout(Duration::from_secs(20))
            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
            .map_err(|err| Error::new(ErrorKind::Other, err))
            .boxed(),
    };

    Ok(transport)
}
