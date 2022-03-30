use turn::auth::*;
use turn::relay::relay_static::*;
use turn::server::config::*;
use turn::Error;
use turn::server::Server;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::Duration;
use clap::Parser;
use util::vnet::net::*;


struct MyAuthHandler {
    cred_map: HashMap<String, Vec<u8>>,
}

impl MyAuthHandler {
    fn new(cred_map: HashMap<String, Vec<u8>>) -> Self {
        MyAuthHandler { cred_map }
    }
}

impl AuthHandler for MyAuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        _src_addr: SocketAddr,
    ) -> Result<Vec<u8>, Error> {
        if let Some(pw) = self.cred_map.get(username) {
            //log::debug!("username={}, password={:?}", username, pw);
            Ok(pw.to_vec())
        } else {
            Err(Error::ErrFakeErr)
        }
    }
}



#[derive(Debug, Parser)]
#[clap(name = "turnsrv")]
struct Opt {
    /// STUN server address.
    #[clap(long, default_value="3478")]
    port: String,

    /// STUN publicip.
    #[clap(long, default_value = "127.0.0.1")]
    ip: String,


    /// Username.
    #[clap(long, default_value = "bns")]
    username: String,

    /// Password.
    #[clap(long, default_value = "password")]
    password: String,

    /// Realm.
    /// REALM
    /// The REALM attribute is present in Shared Secret Requests and Shared
    /// Secret Responses. It contains text which meets the grammar for
    /// "realm" as described in RFC 3261, and will thus contain a quoted
    /// string (including the quotes).
    #[clap(long, default_value = "bns")]
    realm: String,

    /// Nonce.
    #[clap(long, default_value = "qux")]
    nonce: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV,
        "debug"),
    );

    let opt = Opt::parse();
    let port = opt.port;
    let conn = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
    let realm = opt.realm;
    let mut cred_map = HashMap::new();
    let auth = generate_auth_key(&opt.username, &realm, &opt.password);
    cred_map.insert(opt.username, auth);

    println!("listening {}...", conn.local_addr()?);

    let server = Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                relay_address: IpAddr::from_str(&opt.ip)?,
                address: "0.0.0.0".to_owned(),
                net: Arc::new(Net::new(None)),
            }),
        }],
        realm: realm.to_owned(),
        auth_handler: Arc::new(MyAuthHandler::new(cred_map)),
        channel_bind_timeout: Duration::from_secs(0),
    })
        .await?;

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await.expect("failed to listen for event");
    println!("\nClosing connection now...");
    server.close().await?;
    Ok(())
}
