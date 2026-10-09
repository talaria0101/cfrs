//! End-to-end test for the Tailscale socksifying shim.
//!
//! A fake `tailscaled` LocalAPI accepts the `ts-dial` upgrade and echoes
//! whatever is written after it. The real `cfrs net tailscale` front door is
//! started on a unix socket in front of it. A compiled C program calls
//! `connect(AF_INET, 100.64.0.1:1234)` under `LD_PRELOAD` and must reach the
//! echo through the front door, with `getpeername` reporting the logical
//! address rather than the `AF_UNIX` one.
//!
//! This is the whole path the sandbox requires: `AF_UNIX` in, `AF_UNIX` to the
//! daemon, no `AF_INET` connect of the program's own. If no C compiler is
//! available the test reports that and passes, as `shim_direct.rs` does.

use std::io::Write;
use std::process::Command;

use cfrs::vnet::proxy::ProxyListen;
use cfrs::vnet::shim;
use cfrs::vnet::tailscale::{self, Dialer};

fn have_compiler() -> bool {
    shim::compiler().is_ok()
}

fn build_program(dir: &std::path::Path, name: &str, source: &str) -> std::path::PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    std::fs::write(&source_path, source).unwrap();
    let output = dir.join(name);
    let cc = shim::compiler().unwrap();
    let status = Command::new(cc)
        .arg("-O2")
        .arg("-o")
        .arg(&output)
        .arg(&source_path)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {name} failed");
    output
}

/// Accept one `ts-dial` request and echo the bytes that follow it.
async fn fake_tailscaled(listener: tokio::net::UnixListener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).await.unwrap_or(0) == 1 {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&head).contains("Upgrade: ts-dial"),
        "not a ts-dial request"
    );
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: ts-dial\r\nConnection: upgrade\r\n\r\n",
        )
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[test]
fn af_inet_connect_is_redirected_to_the_tailnet_front_door() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let api = dir.path().join("tailscaled.sock");
    let front = dir.path().join("front.sock");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let client = build_program(
        dir.path(),
        "client",
        r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(1234);
  inet_pton(AF_INET,"100.64.0.1",&a.sin_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  if(write(s,"ping",4)!=4){perror("write");return 2;}
  char buf[16]={0}; int n=read(s,buf,15);
  printf("client: got %d bytes: %s\n", n, buf);
  struct sockaddr_in peer; socklen_t pl=sizeof peer;
  if(getpeername(s,(struct sockaddr*)&peer,&pl)==0)
    printf("client: peer %s:%d\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
  close(s); return 0;
}
"#,
    );

    runtime.block_on(async {
        let api_listener = tokio::net::UnixListener::bind(&api).unwrap();
        tokio::spawn(fake_tailscaled(api_listener));
        let proxy = tailscale::serve(Dialer::new(&api), ProxyListen::Unix(front.clone()), 80)
            .await
            .unwrap();

        let shim = shim::build_socks(dir.path()).unwrap();
        let output = Command::new(&client)
            .env("LD_PRELOAD", &shim.path)
            .env("CFRSSOCKS_PROXY", &front)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("got 4 bytes: ping"), "{stdout}");
        assert!(stdout.contains("peer 100.64.0.1:1234"), "{stdout}");
        proxy.abort();
    });

    let _ = std::io::stdout().flush();
}
