//! Finding 4 — Idle clients blocking the daemon.
//!
//! Multiplex bounded nonblocking connections; only complete requests enter the
//! serial dispatcher. Socket I/O never holds the tunnel-operation lock.
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use super::{encode_response_frames, ControlState};
use crate::privileged_api::PrivilegedResponse;

pub(super) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CLIENTS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

struct Client {
    stream: UnixStream,
    input: Vec<u8>,
    output: Vec<u8>,
    written: usize,
    deadline: Instant,
}

impl Client {
    fn new(stream: UnixStream, timeout: Duration) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            input: Vec::new(),
            output: Vec::new(),
            written: 0,
            deadline: Instant::now() + timeout,
        })
    }

    fn step<F>(&mut self, timeout: Duration, dispatch: &mut F) -> anyhow::Result<bool>
    where
        F: FnMut(&str) -> (Vec<String>, PrivilegedResponse),
    {
        // An absolute deadline, not an inactivity timer: one byte per second
        // must not keep a partial request (or blocked response) alive forever.
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "client I/O deadline exceeded"
        );
        if self.output.is_empty() {
            let mut chunk = [0u8; 8192];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Ok(false),
                Ok(n) => self.input.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            anyhow::ensure!(self.input.len() <= MAX_REQUEST_BYTES, "request too large");
            if let Some(end) = self.input.iter().position(|byte| *byte == b'\n') {
                let request = std::str::from_utf8(&self.input[..end])?;
                let (logs, response) = dispatch(request);
                self.output = encode_response_frames(&logs, &response)?;
                anyhow::ensure!(
                    self.output.len() <= MAX_RESPONSE_BYTES,
                    "response too large"
                );
                self.input.drain(..=end);
                self.deadline = Instant::now() + timeout;
            }
        }
        if !self.output.is_empty() {
            match self.stream.write(&self.output[self.written..]) {
                Ok(0) => return Ok(false),
                Ok(n) => self.written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if self.written == self.output.len() {
                self.output.clear();
                self.written = 0;
                self.deadline = Instant::now() + timeout;
            }
        }
        Ok(true)
    }
}

pub(super) fn serve(
    listener: UnixListener,
    state: &mut ControlState,
    idle_timeout: Option<Duration>,
) -> anyhow::Result<()> {
    listener.set_nonblocking(true)?;
    let mut clients = Vec::new();
    let mut last_activity = Instant::now();
    loop {
        for _ in 0..MAX_CLIENTS {
            match listener.accept() {
                Ok((stream, _)) if clients.len() < MAX_CLIENTS => {
                    clients.push(Client::new(stream, IO_TIMEOUT)?);
                }
                Ok(_) => {} // Drop excess connections instead of allocating unbounded state.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        clients.retain_mut(|client| {
            let result = client.step(IO_TIMEOUT, &mut |payload| {
                let result = super::process_request_payload(payload, state, Some((0, 0)));
                last_activity = Instant::now();
                result
            });
            match result {
                Ok(alive) => alive,
                Err(error) => {
                    tracing::debug!(%error, "privileged_client_closed");
                    false
                }
            }
        });
        // Finish queued responses before honoring shutdown. A lease release
        // from one client must not cut off another client's active session.
        if clients.is_empty()
            && (state.should_exit_now()
                || idle_timeout.is_some_and(|timeout| last_activity.elapsed() >= timeout))
        {
            return Ok(());
        }
        wait_for_io(&listener, &clients, last_activity, idle_timeout);
    }
}

/// Sleep until the listener or a client needs attention, or until the next
/// deadline falls due. An on-demand daemon spends most of its life here, so
/// waiting on the descriptors costs nothing while idle; a fixed poll interval
/// would instead wake the CPU hundreds of times a second for no work.
fn wait_for_io(
    listener: &UnixListener,
    clients: &[Client],
    last_activity: Instant,
    idle_timeout: Option<Duration>,
) {
    let mut fds = Vec::with_capacity(clients.len() + 1);
    fds.push(nix::libc::pollfd {
        fd: listener.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    });
    // A client with a queued response is not read again until it drains, so
    // watch for writability there and readability everywhere else.
    let mut wake_at = clients.iter().map(|client| client.deadline).min();
    for client in clients {
        fds.push(nix::libc::pollfd {
            fd: client.stream.as_raw_fd(),
            events: if client.output.is_empty() {
                nix::libc::POLLIN
            } else {
                nix::libc::POLLOUT
            },
            revents: 0,
        });
    }
    if clients.is_empty() {
        wake_at = idle_timeout.map(|timeout| last_activity + timeout);
    }
    let timeout_ms = match wake_at {
        Some(at) => at
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32,
        // Nothing is pending and the daemon never idles out: the next event can
        // only arrive on the listener, so block until it does.
        None => -1,
    };
    let count =
        unsafe { nix::libc::poll(fds.as_mut_ptr(), fds.len() as nix::libc::nfds_t, timeout_ms) };
    if count < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        // The next pass re-derives every deadline from the clock, so a failed
        // wait is recoverable. Pause briefly so it cannot become a hot loop.
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    #[test]
    fn idle_wait_blocks_until_the_timeout_and_wakes_on_connect() {
        let path =
            std::env::temp_dir().join(format!("tunmux-idlewait-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();

        // No clients and 150ms left on the idle timer: the wait must consume it
        // rather than returning at a fixed poll interval.
        let started = Instant::now();
        wait_for_io(&listener, &[], started, Some(Duration::from_millis(150)));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(120),
            "returned after {waited:?}"
        );

        // A pending connection wakes the wait well before a long timeout.
        let peer = UnixStream::connect(&path).unwrap();
        let started = Instant::now();
        wait_for_io(
            &listener,
            &[],
            Instant::now(),
            Some(Duration::from_secs(30)),
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(peer);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn listener_services_request_behind_idle_connection() {
        let path =
            std::env::temp_dir().join(format!("tunmux-listener-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let idle = UnixStream::connect(&path).unwrap();
        let mut active = UnixStream::connect(&path).unwrap();
        active
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            serve(
                listener,
                &mut ControlState::new(false),
                Some(Duration::from_millis(20)),
            )
            .unwrap();
        });
        active
            .write_all(b"{\"kind\":\"lease_acquire\",\"token\":\"1:0\"}\n")
            .unwrap();
        let mut reader = BufReader::new(active);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        assert!(response.contains("unit"));
        drop(reader);
        drop(idle);
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    fn client() -> (Client, UnixStream) {
        let (server, peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        (Client::new(server, IO_TIMEOUT).unwrap(), peer)
    }

    #[test]
    fn idle_client_does_not_block_another_client() {
        let (mut idle, _idle_peer) = client();
        let (mut active, mut active_peer) = client();
        assert!(idle
            .step(IO_TIMEOUT, &mut |_| panic!("idle client dispatched"))
            .unwrap());
        active_peer.write_all(b"status\n").unwrap();
        assert!(active
            .step(IO_TIMEOUT, &mut |_| (
                vec![],
                PrivilegedResponse::Bool(true)
            ))
            .unwrap());
        let mut response = String::new();
        BufReader::new(active_peer)
            .read_line(&mut response)
            .unwrap();
        assert!(response.contains("true"));
    }

    #[test]
    fn trickle_cannot_extend_absolute_deadline() {
        let (mut client, mut peer) = client();
        let deadline = client.deadline;
        peer.write_all(b"{").unwrap();
        client
            .step(IO_TIMEOUT, &mut |_| panic!("partial request dispatched"))
            .unwrap();
        assert_eq!(client.deadline, deadline);
        client.deadline = Instant::now();
        peer.write_all(b" ").unwrap();
        assert!(client
            .step(IO_TIMEOUT, &mut |_| panic!("expired request dispatched"))
            .is_err());
    }

    #[test]
    fn oversized_request_is_rejected_before_dispatch() {
        let (mut client, _peer) = client();
        client.input = vec![b'x'; MAX_REQUEST_BYTES + 1];
        assert!(client
            .step(IO_TIMEOUT, &mut |_| panic!("oversized request dispatched"))
            .is_err());
    }

    #[test]
    fn pipelined_frames_are_preserved() {
        let (mut client, mut peer) = client();
        peer.write_all(b"first\nsecond\n").unwrap();
        let mut requests = Vec::new();
        for _ in 0..2 {
            client
                .step(IO_TIMEOUT, &mut |request| {
                    requests.push(request.to_owned());
                    (vec![], PrivilegedResponse::Unit)
                })
                .unwrap();
        }
        assert_eq!(requests, ["first", "second"]);
    }

    #[test]
    fn unread_response_expires() {
        let (mut client, _peer) = client();
        client.output = vec![b'x'; MAX_RESPONSE_BYTES];
        client.deadline = Instant::now();
        assert!(client
            .step(IO_TIMEOUT, &mut |_| panic!("unexpected dispatch"))
            .is_err());
    }
}
