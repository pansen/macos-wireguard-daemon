//! Finding 4 — Idle clients blocking the daemon.
//!
//! Multiplex bounded nonblocking connections; only complete requests enter the
//! serial dispatcher. Socket I/O never holds the tunnel-operation lock.
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{encode_response_frames, ControlState, RequestOutcome};
use crate::privileged_api::PrivilegedResponse;

pub(super) const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CLIENTS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// A `ConnectConnection`/`DisconnectConnection` worker thread genuinely needs
/// more time than an ordinary request (DNS/network setup, waiting on the
/// gotatun helper); this bounds how long the client's connection is kept open
/// waiting for it, separate from the ordinary per-request `IO_TIMEOUT`.
const PENDING_WORKER_TIMEOUT: Duration = Duration::from_secs(60);
/// How often the accept loop re-checks a pending worker thread's channel when
/// nothing else has woken it. Short enough that a finished worker's response
/// is written promptly; long enough not to busy-loop the accept thread.
const PENDING_POLL_INTERVAL: Duration = Duration::from_millis(20);

struct Client {
    stream: UnixStream,
    /// Real peer credentials from `getpeereid()`, captured once at accept
    /// time (uid is invariant for the connection's life) rather than
    /// re-queried per request.
    peer_uid: u32,
    peer_gid: u32,
    input: Vec<u8>,
    output: Vec<u8>,
    written: usize,
    deadline: Instant,
    /// Set while a `ConnectConnection`/`DisconnectConnection` worker thread
    /// is running for this client's most recent request; see
    /// `dispatch::DispatchOutcome::Pending`.
    pending: Option<mpsc::Receiver<PrivilegedResponse>>,
}

impl Client {
    fn new(stream: UnixStream, timeout: Duration) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        let (peer_uid, peer_gid) = peer_credentials(&stream)?;
        Ok(Self {
            stream,
            peer_uid,
            peer_gid,
            input: Vec::new(),
            output: Vec::new(),
            written: 0,
            deadline: Instant::now() + timeout,
            pending: None,
        })
    }

    fn step<F>(&mut self, timeout: Duration, dispatch: &mut F) -> anyhow::Result<bool>
    where
        F: FnMut(&str, u32, u32) -> RequestOutcome,
    {
        // An absolute deadline, not an inactivity timer: one byte per second
        // must not keep a partial request (or blocked response) alive forever.
        anyhow::ensure!(
            Instant::now() < self.deadline,
            "client I/O deadline exceeded"
        );

        if let Some(rx) = &self.pending {
            // A client that hangs up mid-wait still reports POLLHUP on its fd
            // regardless of the requested event mask (POSIX `poll()`
            // semantics), so `wait_for_io` would otherwise return instantly
            // on every loop iteration until the worker finishes or the
            // pending deadline expires -- a needless busy-spin. Detecting the
            // hangup here and dropping the client (the worker keeps running
            // independently; its eventual response is simply discarded, see
            // `dispatch.rs`'s `let _ = tx.send(response)`) stops that.
            let mut probe = [0u8; 1];
            match self.stream.read(&mut probe) {
                Ok(0) => return Ok(false),
                Ok(_) => {} // A client isn't expected to send more after its request; ignored.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            match rx.try_recv() {
                Ok(response) => {
                    self.output = encode_response_frames(&[], &response)?;
                    anyhow::ensure!(
                        self.output.len() <= MAX_RESPONSE_BYTES,
                        "response too large"
                    );
                    self.pending = None;
                    self.deadline = Instant::now() + timeout;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    anyhow::bail!("worker thread ended without producing a response");
                }
            }
        } else if self.output.is_empty() {
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
                match dispatch(request, self.peer_uid, self.peer_gid) {
                    RequestOutcome::Immediate(logs, response) => {
                        self.output = encode_response_frames(&logs, &response)?;
                        anyhow::ensure!(
                            self.output.len() <= MAX_RESPONSE_BYTES,
                            "response too large"
                        );
                        self.deadline = Instant::now() + timeout;
                    }
                    RequestOutcome::Pending(rx) => {
                        self.pending = Some(rx);
                        self.deadline = Instant::now() + PENDING_WORKER_TIMEOUT;
                    }
                }
                self.input.drain(..=end);
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

/// Real peer credentials for an accepted Unix-domain connection, via macOS's
/// `getpeereid()` (there is no `SO_PEERCRED`/`LOCAL_PEERCRED` sockopt path
/// used here; `getpeereid` is the portable BSD-family call). This is the
/// daemon's first real access-control signal: previously this returned a
/// hardcoded `(0, 0)` used only for a log line, never for authorization (see
/// the design plan's authorization section) -- `dispatch.rs` now uses the uid
/// this returns to decide ownership of global/per-user connections.
fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, u32)> {
    let mut uid: nix::libc::uid_t = 0;
    let mut gid: nix::libc::gid_t = 0;
    // SAFETY: `stream`'s fd is valid for the duration of this call; `uid`/`gid`
    // are valid out-parameters of the correct libc type.
    let ret = unsafe { nix::libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((uid as u32, gid as u32))
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
            let result = client.step(IO_TIMEOUT, &mut |payload, uid, gid| {
                let result = super::process_request_payload(payload, state, Some((uid, gid)));
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
/// would instead wake the CPU hundreds of times a second for no work. The one
/// exception is a client with a `ConnectConnection`/`DisconnectConnection`
/// worker in flight: its completion arrives on a channel, not a file
/// descriptor `poll()` can watch, so the wait is capped at
/// `PENDING_POLL_INTERVAL` whenever any client is pending.
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
    // watch for writability there and readability everywhere else. A pending
    // client is watched for neither: it already sent its complete request and
    // has no response to write yet, so its own fd has nothing new to report.
    let mut wake_at = clients.iter().map(|client| client.deadline).min();
    let any_pending = clients.iter().any(|client| client.pending.is_some());
    for client in clients {
        let events = if client.pending.is_some() {
            0
        } else if client.output.is_empty() {
            nix::libc::POLLIN
        } else {
            nix::libc::POLLOUT
        };
        fds.push(nix::libc::pollfd {
            fd: client.stream.as_raw_fd(),
            events,
            revents: 0,
        });
    }
    if clients.is_empty() {
        wake_at = idle_timeout.map(|timeout| last_activity + timeout);
    }
    let mut timeout_ms = match wake_at {
        Some(at) => at
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32,
        // Nothing is pending and the daemon never idles out: the next event can
        // only arrive on the listener, so block until it does.
        None => -1,
    };
    if any_pending {
        let cap = PENDING_POLL_INTERVAL.as_millis() as i32;
        timeout_ms = if timeout_ms < 0 { cap } else { timeout_ms.min(cap) };
    }
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

    fn immediate(response: PrivilegedResponse) -> RequestOutcome {
        RequestOutcome::Immediate(Vec::new(), response)
    }

    #[test]
    fn idle_client_does_not_block_another_client() {
        let (mut idle, _idle_peer) = client();
        let (mut active, mut active_peer) = client();
        assert!(idle
            .step(IO_TIMEOUT, &mut |_, _, _| panic!("idle client dispatched"))
            .unwrap());
        active_peer.write_all(b"status\n").unwrap();
        assert!(active
            .step(IO_TIMEOUT, &mut |_, _, _| immediate(
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
            .step(IO_TIMEOUT, &mut |_, _, _| panic!("partial request dispatched"))
            .unwrap();
        assert_eq!(client.deadline, deadline);
        client.deadline = Instant::now();
        peer.write_all(b" ").unwrap();
        assert!(client
            .step(IO_TIMEOUT, &mut |_, _, _| panic!("expired request dispatched"))
            .is_err());
    }

    #[test]
    fn oversized_request_is_rejected_before_dispatch() {
        let (mut client, _peer) = client();
        client.input = vec![b'x'; MAX_REQUEST_BYTES + 1];
        assert!(client
            .step(IO_TIMEOUT, &mut |_, _, _| panic!("oversized request dispatched"))
            .is_err());
    }

    #[test]
    fn pipelined_frames_are_preserved() {
        let (mut client, mut peer) = client();
        peer.write_all(b"first\nsecond\n").unwrap();
        let mut requests = Vec::new();
        for _ in 0..2 {
            client
                .step(IO_TIMEOUT, &mut |request, _, _| {
                    requests.push(request.to_owned());
                    immediate(PrivilegedResponse::Unit)
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
            .step(IO_TIMEOUT, &mut |_, _, _| panic!("unexpected dispatch"))
            .is_err());
    }

    #[test]
    fn peer_credentials_reports_the_real_caller_uid() {
        let (server, _peer) = UnixStream::pair().unwrap();
        let (uid, _gid) = peer_credentials(&server).unwrap();
        assert_eq!(uid, nix::unistd::getuid().as_raw());
    }

    #[test]
    fn a_pending_client_yields_no_output_until_the_worker_responds() {
        let (mut client, mut peer) = client();
        peer.write_all(b"connect\n").unwrap();
        let (tx, rx) = mpsc::channel();
        let mut rx = Some(rx);
        assert!(client
            .step(IO_TIMEOUT, &mut |_, _, _| RequestOutcome::Pending(
                rx.take().expect("dispatched exactly once")
            ))
            .unwrap());
        assert!(client.pending.is_some());
        assert!(client.output.is_empty());

        // Still nothing to write while the worker hasn't answered.
        assert!(client
            .step(IO_TIMEOUT, &mut |_, _, _| panic!("must not re-dispatch while pending"))
            .unwrap());
        assert!(client.output.is_empty());

        tx.send(PrivilegedResponse::Unit).unwrap();
        assert!(client
            .step(IO_TIMEOUT, &mut |_, _, _| panic!("must not re-dispatch while pending"))
            .unwrap());
        assert!(client.pending.is_none());
        let mut response = String::new();
        BufReader::new(peer).read_line(&mut response).unwrap();
        assert!(response.contains("unit"));
    }

    #[test]
    fn wait_for_io_polls_frequently_while_any_client_is_pending() {
        let path =
            std::env::temp_dir().join(format!("tunmux-pending-wait-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (mut client, _peer) = client();
        let (_tx, rx) = mpsc::channel();
        client.pending = Some(rx);

        let started = Instant::now();
        wait_for_io(&listener, std::slice::from_ref(&client), started, None);
        // No idle timeout and no client deadline near, but a pending worker
        // still forces a bounded (short) wait rather than blocking forever.
        assert!(started.elapsed() < Duration::from_secs(5));
        std::fs::remove_file(path).unwrap();
    }
}
