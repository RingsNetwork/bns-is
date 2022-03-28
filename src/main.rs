
#[macro_use]
extern crate trackable;
use clap::Parser;
use std::net::SocketAddr;
use rusturn::server::UdpServer;
use rusturn::auth::AuthParams;

#[derive(Debug, Parser)]
#[clap(name = "turnsrv")]
struct Opt {
    /// STUN server address.
    #[clap(long, default_value = "0.0.0.0:3478")]
    server: SocketAddr,

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


fn main() -> Result<(), trackable::error::MainError> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "trace"),
    );

    let opt = Opt::parse();

    let server_addr = opt.server;
    let auth_params = track!(AuthParams::with_realm_and_nonce(
        &opt.username,
        &opt.password,
        &opt.realm,
        &opt.nonce
    ))?;

    let turn_server = track!(fibers_global::execute(UdpServer::start(
        server_addr,
        auth_params,
    )))?;
    track!(fibers_global::execute(turn_server))?;

    Ok(())
}
