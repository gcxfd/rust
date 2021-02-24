#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
mod r#macro;

use async_std::net::UdpSocket;
use failure::Error;

mod init;
mod lib;
mod listen;
mod var;

use init::init;
use listen::listen;

#[async_std::main]
async fn main() -> Result<(), Error> {
  init();

  let port = config_get!(port);
  let host = config_get!(host);
  let host_port = format!(
    "{}:{}",
    if host == "" { "0.0.0.0" } else { host.as_str() },
    if port == "" { "0" } else { port.as_str() }
  );

  let socket = UdpSocket::bind(host_port).await?;
  let addr = socket.local_addr()?;
  info!("listening on {:?}", addr);

  if "" == port {
    config_set!(port, addr.port().to_string());
  };

  // let mut buf = BytesMut::with_capacity(4096);
  // buf.put(&b"hello 2"[..]);
  // socket.send_to(&buf.split(), "47.104.79.244:30110").await?;
  listen(socket).await;
  Ok(())
}

// mod blake3;
// use async_std::task::spawn_blocking;
// use futures::future::join_all;
//
// async fn say_hello(sleep: u64) {
//   let txt = sleep.to_string();
//   let vec = txt.as_bytes().to_vec();
//   println!("begin {}", txt);
//
//   let r = spawn_blocking(|| blake3::hash_leading_zero(vec, 18)).await;
//
//   println!("{} {:?}", txt, r);
// }
//
// #[async_std::main]
// async fn main() {
//   let mut li = vec![];
//   for n in 1..10 {
//     li.push(say_hello(n));
//   }
//   println!("join");
//   join_all(li).await;
// }
