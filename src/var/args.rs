use clap::clap_app;

lazy_static! {
  pub static ref args: clap::ArgMatches = clap_app!(myapp =>
    (version: "0.0.1")
    (@arg dir: -d --dir +takes_value "workdir")
    (@arg port: -p --port +takes_value "port")
    (@arg host: --host +takes_value "host")
  )
  .get_matches();
}
