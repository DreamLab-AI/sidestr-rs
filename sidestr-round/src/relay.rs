//! The relay I/O (feature `relay`): a tokio + tokio-tungstenite client
//! that follows relays with reconnection and publishes to them, and an
//! in-process NIP-01 relay stand-in for tests and one-box runs. The rules
//! — filters, the on-receipt checks, what a publish outcome means — are
//! `sidestr-nostr`'s ([`sidestr_nostr::relay`]); this module is only the
//! sockets, so the state machines stay free of them.
//!
//! # TLS
//!
//! `wss://` is served by rustls with the `ring` provider and the Mozilla
//! root store (`webpki-roots`), built once by [`default_connector`] — the
//! provider is named explicitly, so a downstream crate that also enables
//! `aws-lc-rs` cannot make the follower panic on an ambiguous default.
//! [`follow_with`] and [`publish_one_with`] take another
//! [`Connector`] (a private root, a test certificate); [`follow`] and
//! [`publish_one`] use the default. No `native-tls`.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sidestr_nostr::event::Event;
use sidestr_nostr::relay::{ClientMessage, Filter, PublishOutcome, RelayMessage};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
pub use tokio_tungstenite::Connector;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// Seconds since the epoch.
pub fn unix_now() -> u64 {
    unix_now_ms() / 1000
}

/// Milliseconds since the epoch: the rounds' clock.
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The TLS client configuration `wss://` uses: rustls, the `ring`
/// provider, TLS 1.2 and 1.3, the Mozilla root store, no client
/// certificate. Built once per process and used by the default connection
/// pool.
pub fn default_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .expect("ring supports TLS 1.2 and 1.3")
                .with_root_certificates(roots)
                .with_no_client_auth(),
            )
        })
        .clone()
}

/// [`Connector::Rustls`] over [`default_tls_config`]: what `ws://` and
/// `wss://` URLs are opened with unless a caller says otherwise.
pub fn default_connector() -> Connector {
    Connector::Rustls(default_tls_config())
}

/// One websocket connection to `url`, plain or TLS by its scheme. The
/// error is boxed: tungstenite's is large and this is the cold path.
async fn connect(
    url: &str,
    connector: &Connector,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, Box<tokio_tungstenite::tungstenite::Error>>
{
    tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector.clone()))
        .await
        .map(|(ws, _)| ws)
        .map_err(Box::new)
}

type RelaySocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Clone)]
struct Session {
    commands: mpsc::UnboundedSender<PoolCommand>,
}

struct PoolInner {
    connector: Connector,
    sessions: tokio::sync::Mutex<HashMap<String, Session>>,
    sequence: AtomicU64,
}

/// A process-local relay connection pool. One reconnecting websocket is
/// kept per URL and shared by long-lived subscriptions, one-shot fetches and
/// publishes. It closes two seconds after the last user leaves, so a CLI
/// command does not leave a runtime alive (`relay.mjs socket`, issue 14).
#[derive(Clone)]
pub struct RelayPool {
    inner: Arc<PoolInner>,
}

impl std::fmt::Debug for RelayPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayPool").finish_non_exhaustive()
    }
}

enum PoolCommand {
    Subscribe {
        id: String,
        filters: Vec<Filter>,
        one_shot: bool,
        events: mpsc::UnboundedSender<PoolItem>,
    },
    Unsubscribe(String),
    Publish {
        event: Event,
        reply: oneshot::Sender<PublishOutcome>,
    },
}

enum PoolItem {
    Event(Event),
    Eose,
    Closed,
}

struct Subscription {
    filters: Vec<Filter>,
    one_shot: bool,
    events: mpsc::UnboundedSender<PoolItem>,
}

struct PendingPublish {
    event: Event,
    replies: Vec<oneshot::Sender<PublishOutcome>>,
    sent: bool,
}

struct SubscriptionGuard {
    id: String,
    commands: mpsc::UnboundedSender<PoolCommand>,
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        let _ = self
            .commands
            .send(PoolCommand::Unsubscribe(self.id.clone()));
    }
}

impl RelayPool {
    /// An empty pool using `connector` for every URL it opens.
    pub fn new(connector: Connector) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                connector,
                sessions: tokio::sync::Mutex::new(HashMap::new()),
                sequence: AtomicU64::new(1),
            }),
        }
    }

    async fn session(&self, url: &str) -> Session {
        let mut sessions = self.inner.sessions.lock().await;
        if let Some(session) = sessions.get(url).filter(|s| !s.commands.is_closed()) {
            return session.clone();
        }
        let (commands, rx) = mpsc::unbounded_channel();
        let session = Session {
            commands: commands.clone(),
        };
        sessions.insert(url.to_string(), session.clone());
        tokio::spawn(run_session(
            url.to_string(),
            self.inner.connector.clone(),
            rx,
        ));
        session
    }

    async fn subscribe(
        &self,
        url: &str,
        filters: Vec<Filter>,
        one_shot: bool,
    ) -> (mpsc::UnboundedReceiver<PoolItem>, SubscriptionGuard) {
        let session = self.session(url).await;
        let sequence = self.inner.sequence.fetch_add(1, Ordering::Relaxed);
        let id = format!("sidestr-{sequence:020}");
        let (events, rx) = mpsc::unbounded_channel();
        let _ = session.commands.send(PoolCommand::Subscribe {
            id: id.clone(),
            filters,
            one_shot,
            events,
        });
        (
            rx,
            SubscriptionGuard {
                id,
                commands: session.commands,
            },
        )
    }

    /// Follow all `kinds` on each relay over this pool. Every reconnect
    /// re-sends the subscription before events resume.
    pub fn follow(
        &self,
        relays: Vec<String>,
        kinds: Vec<u32>,
        since_secs: u64,
        log: impl Fn(String) + Send + Sync + 'static,
    ) -> mpsc::Receiver<(String, Event)> {
        let (tx, rx) = mpsc::channel(1024);
        let log = Arc::new(log);
        for url in relays {
            let pool = self.clone();
            let tx = tx.clone();
            let kinds = kinds.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut feeds = Vec::with_capacity(kinds.len());
                for kind in kinds {
                    let filter = sidestr_nostr::relay::follow_filter(kind, since_secs, unix_now());
                    let feed = pool.subscribe(&url, vec![filter], false).await;
                    log(format!("relay {url}: following kind {kind}"));
                    feeds.push(feed);
                }
                for (mut events, guard) in feeds {
                    let tx = tx.clone();
                    let url = url.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        loop {
                            tokio::select! {
                                _ = tx.closed() => break,
                                item = events.recv() => match item {
                                    Some(PoolItem::Event(event)) => {
                                        if tx.send((url.clone(), event)).await.is_err() { break; }
                                    }
                                    Some(PoolItem::Eose) => {}
                                    Some(PoolItem::Closed) | None => break,
                                }
                            }
                        }
                    });
                }
            });
        }
        rx
    }

    async fn fetch_one(&self, url: &str, filter: Filter, timeout: Duration) -> Vec<Event> {
        let (mut events, _guard) = self.subscribe(url, vec![filter], true).await;
        let mut found = Vec::new();
        let read = async {
            while let Some(item) = events.recv().await {
                match item {
                    PoolItem::Event(event) => found.push(event),
                    PoolItem::Eose | PoolItem::Closed => break,
                }
            }
        };
        let _ = tokio::time::timeout(timeout, read).await;
        found
    }

    /// Fetch from every relay through this pool until `EOSE` or `timeout`.
    pub async fn fetch(&self, relays: &[String], filter: Filter, timeout: Duration) -> Vec<Event> {
        let one = |url: String| {
            let pool = self.clone();
            let filter = filter.clone();
            async move { pool.fetch_one(&url, filter, timeout).await }
        };
        futures_util::future::join_all(relays.iter().cloned().map(one))
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// Publish through the URL's shared socket and wait for its `OK`.
    pub async fn publish_one(&self, url: &str, event: &Event, timeout: Duration) -> PublishOutcome {
        let wait = async {
            let session = self.session(url).await;
            let (reply, rx) = oneshot::channel();
            if session
                .commands
                .send(PoolCommand::Publish {
                    event: event.clone(),
                    reply,
                })
                .is_err()
            {
                return PublishOutcome::Closed;
            }
            rx.await.unwrap_or(PublishOutcome::Closed)
        };
        tokio::time::timeout(timeout, wait)
            .await
            .unwrap_or(PublishOutcome::Timeout)
    }
}

fn default_pool() -> &'static RelayPool {
    static POOL: OnceLock<RelayPool> = OnceLock::new();
    POOL.get_or_init(|| RelayPool::new(default_connector()))
}

async fn send_client(socket: &mut RelaySocket, message: ClientMessage) -> bool {
    socket
        .send(Message::Text(message.to_json().into()))
        .await
        .is_ok()
}

fn close_publishes(publishes: &mut HashMap<String, PendingPublish>) {
    for (_, pending) in publishes.drain() {
        for reply in pending.replies {
            let _ = reply.send(PublishOutcome::Closed);
        }
    }
}

async fn apply_command(
    command: PoolCommand,
    subscriptions: &mut BTreeMap<String, Subscription>,
    publishes: &mut HashMap<String, PendingPublish>,
    socket: &mut Option<RelaySocket>,
) -> bool {
    match command {
        PoolCommand::Subscribe {
            id,
            filters,
            one_shot,
            events,
        } => {
            let request = ClientMessage::Req {
                subscription_id: id.clone(),
                filters: filters.clone(),
            };
            subscriptions.insert(
                id,
                Subscription {
                    filters,
                    one_shot,
                    events,
                },
            );
            match socket.as_mut() {
                Some(socket) => send_client(socket, request).await,
                None => true,
            }
        }
        PoolCommand::Unsubscribe(id) => {
            let existed = subscriptions.remove(&id).is_some();
            match (existed, socket.as_mut()) {
                (true, Some(socket)) => send_client(socket, ClientMessage::Close(id)).await,
                _ => true,
            }
        }
        PoolCommand::Publish { event, reply } => {
            let id = event.id.clone();
            if let Some(pending) = publishes.get_mut(&id) {
                pending.replies.push(reply);
                return true;
            }
            publishes.insert(
                id.clone(),
                PendingPublish {
                    event: event.clone(),
                    replies: vec![reply],
                    sent: false,
                },
            );
            if let Some(socket) = socket.as_mut() {
                if send_client(socket, ClientMessage::Event(event)).await {
                    if let Some(pending) = publishes.get_mut(&id) {
                        pending.sent = true;
                    }
                    true
                } else {
                    if let Some(pending) = publishes.remove(&id) {
                        for reply in pending.replies {
                            let _ = reply.send(PublishOutcome::Closed);
                        }
                    }
                    false
                }
            } else {
                true
            }
        }
    }
}

async fn connected(
    socket: &mut RelaySocket,
    subscriptions: &BTreeMap<String, Subscription>,
    publishes: &mut HashMap<String, PendingPublish>,
) -> bool {
    for (id, subscription) in subscriptions {
        if !send_client(
            socket,
            ClientMessage::Req {
                subscription_id: id.clone(),
                filters: subscription.filters.clone(),
            },
        )
        .await
        {
            return false;
        }
    }
    for pending in publishes.values_mut() {
        if !send_client(socket, ClientMessage::Event(pending.event.clone())).await {
            return false;
        }
        pending.sent = true;
    }
    true
}

async fn relay_message(
    message: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    socket: &mut RelaySocket,
    subscriptions: &mut BTreeMap<String, Subscription>,
    publishes: &mut HashMap<String, PendingPublish>,
) -> bool {
    let text = match message {
        Some(Ok(Message::Text(text))) => text.to_string(),
        Some(Ok(Message::Ping(bytes))) => {
            return socket.send(Message::Pong(bytes)).await.is_ok();
        }
        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return false,
        _ => return true,
    };
    match RelayMessage::from_json(&text) {
        Ok(RelayMessage::Event {
            subscription_id,
            event,
        }) => {
            let failed = subscriptions
                .get(&subscription_id)
                .is_some_and(|s| s.events.send(PoolItem::Event(event)).is_err());
            if failed {
                subscriptions.remove(&subscription_id);
            }
        }
        Ok(RelayMessage::Eose(id)) => {
            let one_shot = subscriptions.get(&id).is_some_and(|s| {
                let _ = s.events.send(PoolItem::Eose);
                s.one_shot
            });
            if one_shot {
                subscriptions.remove(&id);
                let _ = send_client(socket, ClientMessage::Close(id)).await;
            }
        }
        Ok(RelayMessage::Closed(id, _)) => {
            if let Some(subscription) = subscriptions.remove(&id) {
                let _ = subscription.events.send(PoolItem::Closed);
            }
        }
        Ok(RelayMessage::Ok {
            event_id,
            accepted,
            message,
        }) => {
            if let Some(pending) = publishes.remove(&event_id) {
                let outcome = PublishOutcome::from_ok(accepted, &message);
                for reply in pending.replies {
                    let _ = reply.send(outcome.clone());
                }
            }
        }
        _ => {}
    }
    true
}

async fn run_session(
    url: String,
    connector: Connector,
    mut commands: mpsc::UnboundedReceiver<PoolCommand>,
) {
    let mut subscriptions = BTreeMap::<String, Subscription>::new();
    let mut publishes = HashMap::<String, PendingPublish>::new();
    let mut socket = None;
    let mut backoff = 1u64;
    let mut retry_after = Duration::ZERO;
    loop {
        subscriptions.retain(|_, subscription| !subscription.events.is_closed());
        for pending in publishes.values_mut() {
            pending.replies.retain(|reply| !reply.is_closed());
        }
        publishes.retain(|_, pending| !pending.replies.is_empty());
        let idle = subscriptions.is_empty() && publishes.is_empty();

        if socket.is_none() {
            if idle {
                match tokio::time::timeout(Duration::from_secs(2), commands.recv()).await {
                    Ok(Some(command)) => {
                        let _ =
                            apply_command(command, &mut subscriptions, &mut publishes, &mut socket)
                                .await;
                        continue;
                    }
                    _ => break,
                }
            }
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => { let _ = apply_command(command, &mut subscriptions, &mut publishes, &mut socket).await; }
                    None => break,
                },
                _ = tokio::time::sleep(retry_after) => {
                    match connect(&url, &connector).await {
                        Ok(mut opened) => {
                            if connected(&mut opened, &subscriptions, &mut publishes).await {
                                socket = Some(opened);
                                backoff = 1;
                                retry_after = Duration::ZERO;
                            } else {
                                close_publishes(&mut publishes);
                                retry_after = Duration::from_secs(backoff);
                                backoff = (backoff * 2).min(60);
                            }
                        }
                        Err(_) => {
                            close_publishes(&mut publishes);
                            retry_after = Duration::from_secs(backoff);
                            backoff = (backoff * 2).min(60);
                        }
                    }
                }
            }
            continue;
        }

        let sleep = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(sleep);
        let alive = tokio::select! {
            command = commands.recv() => match command {
                Some(command) => apply_command(command, &mut subscriptions, &mut publishes, &mut socket).await,
                None => break,
            },
            message = socket.as_mut().expect("checked above").next() => {
                relay_message(
                    message,
                    socket.as_mut().expect("checked above"),
                    &mut subscriptions,
                    &mut publishes,
                ).await
            },
            _ = &mut sleep, if idle => break,
        };
        if !alive {
            close_publishes(&mut publishes);
            socket = None;
            retry_after = Duration::from_secs(backoff);
            backoff = (backoff * 2).min(60);
        }
    }
    if let Some(mut socket) = socket {
        let _ = socket.close(None).await;
    }
    close_publishes(&mut publishes);
}

/// Follow `relays` for these kinds since `since_secs` ago (`relay.mjs
/// subscribe`): one `REQ` per kind, by kind only (relays refuse `#chain`),
/// reconnecting with backoff from 1 s to 60 s. Every `EVENT` a relay sends
/// arrives on the channel unverified, tagged with the relay's URL; the
/// chain tag, the signature and duplicates are the consumer's business
/// ([`sidestr_nostr::relay::Follower`], which the rounds apply).
pub fn follow(
    relays: Vec<String>,
    kinds: Vec<u32>,
    since_secs: u64,
    log: impl Fn(String) + Send + Sync + 'static,
) -> mpsc::Receiver<(String, Event)> {
    default_pool().follow(relays, kinds, since_secs, log)
}

/// [`follow`] with the TLS connector given.
pub fn follow_with(
    relays: Vec<String>,
    kinds: Vec<u32>,
    since_secs: u64,
    log: impl Fn(String) + Send + Sync + 'static,
    connector: Connector,
) -> mpsc::Receiver<(String, Event)> {
    RelayPool::new(connector).follow(relays, kinds, since_secs, log)
}

/// Ask each relay once for the events matching `filter` and collect what they
/// send until each says `EOSE` (or closes, or `timeout` passes): the one-shot
/// read `announce.mjs fetchLatestTip` makes, where [`follow`] stays open.
/// Events arrive unverified, in no particular order and possibly duplicated
/// across relays; the caller verifies and chooses
/// ([`sidestr_nostr::tip::newest`] does both for announcements).
pub async fn fetch(relays: &[String], filter: Filter, timeout: Duration) -> Vec<Event> {
    default_pool().fetch(relays, filter, timeout).await
}

/// [`fetch`] with the TLS connector given.
pub async fn fetch_with(
    relays: &[String],
    filter: Filter,
    timeout: Duration,
    connector: &Connector,
) -> Vec<Event> {
    RelayPool::new(connector.clone())
        .fetch(relays, filter, timeout)
        .await
}

/// Publish one event to one relay and report what it said (`relay.mjs
/// publish`): `["EVENT", …]` over the shared socket, then the `OK` for this
/// id within `timeout`.
pub async fn publish_one(url: &str, event: &Event, timeout: Duration) -> PublishOutcome {
    default_pool().publish_one(url, event, timeout).await
}

/// [`publish_one`] with the TLS connector given.
pub async fn publish_one_with(
    url: &str,
    event: &Event,
    timeout: Duration,
    connector: &Connector,
) -> PublishOutcome {
    RelayPool::new(connector.clone())
        .publish_one(url, event, timeout)
        .await
}

/// Publish to every relay at once; each one's verdict, in order. Upstream's
/// timeout is 8 s.
pub async fn publish_all(
    relays: &[String],
    event: &Event,
    timeout: Duration,
) -> Vec<(String, PublishOutcome)> {
    let mut out = Vec::with_capacity(relays.len());
    let results =
        futures_util::future::join_all(relays.iter().map(|r| publish_one(r, event, timeout))).await;
    for (r, o) in relays.iter().zip(results) {
        out.push((r.clone(), o));
    }
    out
}

/// How many said `ok`.
pub fn ok_count(results: &[(String, PublishOutcome)]) -> usize {
    results
        .iter()
        .filter(|(_, o)| *o == PublishOutcome::Ok)
        .count()
}

// --- the stand-in ------------------------------------------------------------------

fn matches(f: &Filter, ev: &Event) -> bool {
    (f.kinds.is_empty() || f.kinds.contains(&ev.kind))
        && (f.authors.is_empty() || f.authors.iter().any(|a| ev.pubkey.eq_ignore_ascii_case(a)))
        && (f.d.is_empty()
            || ev
                .tags
                .iter()
                .any(|t| t.len() > 1 && t[0] == "d" && f.d.contains(&t[1])))
        && (f.t.is_empty()
            || ev
                .tags
                .iter()
                .any(|t| t.len() > 1 && t[0] == "t" && f.t.contains(&t[1])))
        && f.since.is_none_or(|s| ev.created_at >= s)
}

/// A NIP-01 relay in a process: `REQ` / `EVENT` / `CLOSE` in, `EVENT` /
/// `EOSE` / `OK` / `CLOSED` out, events kept in memory and verified on
/// arrival, plain or behind TLS ([`RelayStandIn::start_tls`]). Enough for
/// three signers on one box and for the interop tests; **not a relay** —
/// no persistence, no limits, no auth, one process.
#[derive(Debug)]
pub struct RelayStandIn {
    addr: SocketAddr,
    tls: bool,
    events: Arc<Mutex<Vec<Event>>>,
    connections: Arc<AtomicUsize>,
    _live: broadcast::Sender<Event>,
}

impl RelayStandIn {
    /// Listen on `bind` (`127.0.0.1:0` for any free port) and serve until
    /// dropped.
    pub async fn start(bind: &str) -> std::io::Result<Self> {
        Self::start_with(bind, None).await
    }

    /// [`RelayStandIn::start`] behind TLS with this server configuration
    /// (a certificate for the name the client will dial), so a `wss://`
    /// client can be tested without a network.
    pub async fn start_tls(bind: &str, tls: Arc<rustls::ServerConfig>) -> std::io::Result<Self> {
        Self::start_with(bind, Some(tls)).await
    }

    async fn start_with(
        bind: &str,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (live, _) = broadcast::channel::<Event>(4096);
        let store = events.clone();
        let sender = live.clone();
        let accepted = connections.clone();
        let acceptor = tls.clone().map(tokio_rustls::TlsAcceptor::from);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                accepted.fetch_add(1, Ordering::Relaxed);
                let (store, sender) = (store.clone(), sender.clone());
                match acceptor.clone() {
                    None => {
                        tokio::spawn(serve(stream, store, sender));
                    }
                    Some(acceptor) => {
                        tokio::spawn(async move {
                            if let Ok(tls) = acceptor.accept(stream).await {
                                serve(tls, store, sender).await;
                            }
                        });
                    }
                }
            }
        });
        Ok(Self {
            addr,
            tls: tls.is_some(),
            events,
            connections,
            _live: live,
        })
    }
    /// `ws://127.0.0.1:<port>`, or `wss://localhost:<port>` behind TLS
    /// (the certificate is expected to name `localhost`).
    pub fn url(&self) -> String {
        if self.tls {
            format!("wss://localhost:{}", self.addr.port())
        } else {
            format!("ws://{}", self.addr)
        }
    }
    /// Everything accepted so far, in arrival order.
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
    /// Websocket connections accepted since the stand-in started.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    store: Arc<Mutex<Vec<Event>>>,
    live: broadcast::Sender<Event>,
) {
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    let mut subs: HashMap<String, Vec<Filter>> = HashMap::new();
    let mut rx = live.subscribe();
    loop {
        tokio::select! {
            msg = ws.next() => {
                let text = match msg {
                    Some(Ok(Message::Text(t))) => t.to_string(),
                    Some(Ok(Message::Ping(p))) => { let _ = ws.send(Message::Pong(p)).await; continue; }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    _ => continue,
                };
                let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(&text) else { continue };
                match v.first().and_then(|x| x.as_str()) {
                    Some("REQ") => {
                        let Some(id) = v.get(1).and_then(|x| x.as_str()) else { continue };
                        let filters: Vec<Filter> = v[2..].iter().filter_map(|f| serde_json::from_value(f.clone()).ok()).collect();
                        let mut stored: Vec<Event> = store.lock().map(|s| s.clone()).unwrap_or_default();
                        stored.sort_by_key(|a| std::cmp::Reverse(a.created_at));
                        let limit = filters.iter().filter_map(|f| f.limit).max();
                        let mut sent = 0usize;
                        for ev in stored {
                            if filters.iter().any(|f| matches(f, &ev)) {
                                if limit.is_some_and(|l| sent >= l as usize) { break; }
                                let m = serde_json::to_string(&("EVENT", id, &ev)).expect("plain fields");
                                if ws.send(Message::Text(m.into())).await.is_err() { return; }
                                sent += 1;
                            }
                        }
                        let eose = serde_json::to_string(&("EOSE", id)).expect("plain fields");
                        if ws.send(Message::Text(eose.into())).await.is_err() { return; }
                        subs.insert(id.to_string(), filters);
                    }
                    Some("EVENT") => {
                        let Some(ev) = v.get(1).and_then(|e| serde_json::from_value::<Event>(e.clone()).ok()) else { continue };
                        let (ok, why) = match ev.verify() {
                            Ok(()) => (true, ""),
                            Err(_) => (false, "invalid: bad signature"),
                        };
                        if ok {
                            let fresh = store.lock().map(|mut s| {
                                if s.iter().any(|e| e.id == ev.id) { false } else { s.push(ev.clone()); true }
                            }).unwrap_or(false);
                            if fresh { let _ = live.send(ev.clone()); }
                        }
                        let m = serde_json::to_string(&("OK", &ev.id, ok, why)).expect("plain fields");
                        if ws.send(Message::Text(m.into())).await.is_err() { return; }
                    }
                    Some("CLOSE") => {
                        if let Some(id) = v.get(1).and_then(|x| x.as_str()) { subs.remove(id); }
                    }
                    _ => {
                        let m = serde_json::to_string(&("NOTICE", "unknown verb")).expect("plain fields");
                        let _ = ws.send(Message::Text(m.into())).await;
                    }
                }
            }
            ev = rx.recv() => {
                let Ok(ev) = ev else { continue };
                for (id, filters) in &subs {
                    if filters.iter().any(|f| matches(f, &ev)) {
                        let m = serde_json::to_string(&("EVENT", id, &ev)).expect("plain fields");
                        if ws.send(Message::Text(m.into())).await.is_err() { return; }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidestr_nostr::event::SecretKeySigner;
    use sidestr_nostr::tx::sign_transaction_event;

    #[tokio::test]
    async fn the_stand_in_stores_replays_and_pushes_and_the_client_follows_and_publishes() {
        let relay = RelayStandIn::start("127.0.0.1:0").await.unwrap();
        let url = relay.url();
        let signer = SecretKeySigner::from_bytes(&[3u8; 32]).unwrap();
        let now = unix_now();
        let old = sign_transaction_event(&signer, "sidestr:t", "0200", now - 10).unwrap();
        assert_eq!(
            publish_one(&url, &old, Duration::from_secs(5)).await,
            PublishOutcome::Ok
        );
        let mut forged = old.clone();
        forged.content = "0300".into();
        assert!(matches!(
            publish_one(&url, &forged, Duration::from_secs(5)).await,
            PublishOutcome::Rejected(_)
        ));
        let mut rx = follow(vec![url.clone()], vec![23500], 600, |_| {});
        let (_, got) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, old, "stored events are replayed");
        let fresh = sign_transaction_event(&signer, "sidestr:t", "0201", now).unwrap();
        let r = publish_all(
            &[url.clone(), "ws://127.0.0.1:1".into()],
            &fresh,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(ok_count(&r), 1);
        let (_, got) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, fresh, "live events are pushed");
        assert_eq!(relay.events().len(), 2);
        // a filter by #d and limit, as fetchLatestTip asks
        let tip = sidestr_nostr::tip::sign_tip(
            &signer,
            &sidestr_nostr::tip::TipTemplate::new("sidestr:t", 0, vec![], vec![]).unwrap(),
            now,
        )
        .unwrap();
        publish_one(&url, &tip, Duration::from_secs(5)).await;
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        ws.send(Message::Text(
            ClientMessage::Req {
                subscription_id: "tip".into(),
                filters: vec![sidestr_nostr::relay::tip_filter("sidestr:t")],
            }
            .to_json()
            .into(),
        ))
        .await
        .unwrap();
        let mut got = Vec::new();
        while let Some(Ok(Message::Text(t))) = ws.next().await {
            match RelayMessage::from_json(&t).unwrap() {
                RelayMessage::Event { event, .. } => got.push(event),
                RelayMessage::Eose(_) => break,
                _ => {}
            }
        }
        assert_eq!(got, vec![tip.clone()]);
        // the one-shot read: until EOSE, a dead relay costing only its own timeout
        let fetched = fetch(
            &[url.clone(), "ws://127.0.0.1:1".into()],
            sidestr_nostr::relay::tip_filter("sidestr:t"),
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(fetched, vec![tip]);
    }

    #[tokio::test]
    async fn one_pool_shares_a_socket_then_closes_it_when_idle() {
        let relay = RelayStandIn::start("127.0.0.1:0").await.unwrap();
        let url = relay.url();
        let pool = RelayPool::new(default_connector());
        let signer = SecretKeySigner::from_bytes(&[4u8; 32]).unwrap();
        let now = unix_now();
        let mut followed = pool.follow(vec![url.clone()], vec![23500], 600, |_| {});
        let first = sign_transaction_event(&signer, "sidestr:pool", "0200", now).unwrap();
        assert_eq!(
            pool.publish_one(&url, &first, Duration::from_secs(5)).await,
            PublishOutcome::Ok
        );
        let (_, received) = tokio::time::timeout(Duration::from_secs(5), followed.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, first);

        let fetched = pool
            .fetch(
                std::slice::from_ref(&url),
                Filter {
                    kinds: vec![23500],
                    ..Filter::default()
                },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(fetched, vec![first]);
        assert_eq!(relay.connections(), 1, "follow, fetch and publish share");

        drop(followed);
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        let second = sign_transaction_event(&signer, "sidestr:pool", "0201", now + 1).unwrap();
        assert_eq!(
            pool.publish_one(&url, &second, Duration::from_secs(5))
                .await,
            PublishOutcome::Ok
        );
        assert_eq!(
            relay.connections(),
            2,
            "the idle socket closed and a later operation reopened it"
        );
    }
}
