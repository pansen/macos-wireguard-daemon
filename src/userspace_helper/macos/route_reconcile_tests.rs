use super::*;
use std::cell::{Cell, RefCell};

fn tunnel_route(destination: &str) -> MacosRoute {
    MacosRoute {
        destination: destination.into(),
        is_ipv6: destination.contains(':'),
        interface: Some("utun6".into()),
        gateway: None,
    }
}

fn routing(routes_added: Vec<MacosRoute>) -> MacosRoutingState {
    MacosRoutingState {
        routes_added,
        fingerprint: MacosNetworkFingerprint::default(),
        failing: Vec::new(),
    }
}

#[test]
fn failed_delete_stays_owned_until_retry_succeeds() {
    let route = tunnel_route("10.66.77.0/24");
    let mut state = routing(vec![route.clone()]);
    let restored = RefCell::new(Vec::new());
    for retry_only in [false, true] {
        let result = macos_apply_route_plan(
            &mut state,
            vec![],
            retry_only,
            &|_| anyhow::bail!("temporarily unavailable"),
            &|_| panic!("nothing to add"),
            &|route| restored.borrow_mut().push(route.clone()),
        );
        assert_eq!(result.errors, 1);
        assert_eq!(
            state.routes_added,
            vec![route.clone()],
            "also kept for teardown"
        );
        assert_eq!(state.failing.len(), 1);
        assert_eq!(state.failing[0].operation, MacosRouteOperation::Delete);
        assert!(restored.borrow().is_empty());
    }
    let result = macos_apply_route_plan(
        &mut state,
        vec![],
        true,
        &|_| Ok(()),
        &|_| panic!("nothing to add"),
        &|route| restored.borrow_mut().push(route.clone()),
    );
    assert_eq!(result.removed, 1);
    assert!(state.routes_added.is_empty());
    assert!(state.failing.is_empty());
    assert_eq!(*restored.borrow(), vec![route]);
}

#[test]
fn failed_add_retries_without_revisiting_foreign_routes() {
    let route = tunnel_route("192.168.188.1/32");
    let foreign = tunnel_route("192.168.188.2/32");
    let desired = vec![route.clone(), foreign.clone()];
    let mut state = routing(vec![]);
    macos_apply_route_plan(
        &mut state,
        desired.clone(),
        false,
        &|_| panic!("nothing to delete"),
        &|candidate| {
            if candidate == &foreign {
                Ok(MacosRouteInstall::Foreign)
            } else {
                anyhow::bail!("temporarily unavailable")
            }
        },
        &|_| panic!("nothing to restore"),
    );
    assert!(state.routes_added.is_empty());
    assert_eq!(state.failing.len(), 1);
    let result = macos_apply_route_plan(
        &mut state,
        desired,
        true,
        &|_| panic!("nothing to delete"),
        &|candidate| {
            assert_eq!(candidate, &route);
            Ok(MacosRouteInstall::Owned)
        },
        &|_| panic!("nothing to restore"),
    );
    assert_eq!(result.added, 1);
    assert_eq!(state.routes_added, vec![route]);
    assert!(state.failing.is_empty());
}

#[test]
fn a_new_plan_cancels_obsolete_retries() {
    let route = tunnel_route("10.66.77.0/24");
    let mut state = routing(vec![route.clone()]);
    macos_apply_route_plan(
        &mut state,
        vec![],
        false,
        &|_| anyhow::bail!("temporarily unavailable"),
        &|_| panic!("nothing to add"),
        &|_| panic!("nothing to restore"),
    );
    // The LAN disappears again before deletion succeeded: keep the route.
    macos_apply_route_plan(
        &mut state,
        vec![route.clone()],
        false,
        &|_| panic!("the route is desired again"),
        &|_| panic!("the route is still present"),
        &|_| panic!("nothing to restore"),
    );
    assert_eq!(state.routes_added, vec![route.clone()]);
    assert!(state.failing.is_empty());

    let mut state = routing(vec![]);
    macos_apply_route_plan(
        &mut state,
        vec![route],
        false,
        &|_| panic!("nothing to delete"),
        &|_| anyhow::bail!("temporarily unavailable"),
        &|_| panic!("nothing to restore"),
    );
    macos_apply_route_plan(
        &mut state,
        vec![],
        false,
        &|_| panic!("nothing to delete"),
        &|_| panic!("the route is no longer desired"),
        &|_| panic!("nothing to restore"),
    );
    assert!(state.failing.is_empty());
}

#[test]
fn endpoint_replacement_waits_for_the_old_pin_to_be_removed() {
    let old = MacosRoute {
        destination: "203.0.113.7".into(),
        is_ipv6: false,
        interface: None,
        gateway: Some("10.66.77.1".into()),
    };
    let new = MacosRoute {
        gateway: Some("192.168.1.1".into()),
        ..old.clone()
    };
    let kernel = RefCell::new(Some(old.clone()));
    let adds = Cell::new(0);
    let add = |route: &MacosRoute| {
        adds.set(adds.get() + 1);
        // The real route command treats EEXIST as success, even if the old
        // gateway is still installed. The planner must not attempt this add.
        if kernel.borrow().is_none() {
            *kernel.borrow_mut() = Some(route.clone());
        }
        Ok(MacosRouteInstall::Owned)
    };
    let mut state = routing(vec![old.clone()]);
    macos_apply_route_plan(
        &mut state,
        vec![new.clone()],
        false,
        &|_| anyhow::bail!("temporarily unavailable"),
        &add,
        &|_| {},
    );
    assert_eq!(
        adds.get(),
        0,
        "do not claim a replacement while its old route survives"
    );
    assert_eq!(state.routes_added, vec![old]);

    let result = macos_apply_route_plan(
        &mut state,
        vec![new.clone()],
        true,
        &|_| {
            *kernel.borrow_mut() = None;
            Ok(())
        },
        &add,
        &|_| {},
    );
    assert_eq!((result.removed, result.added), (1, 1));
    assert_eq!(*kernel.borrow(), Some(new.clone()));
    assert_eq!(state.routes_added, vec![new]);
    assert!(state.failing.is_empty());
}

#[test]
fn retry_logging_warns_once_and_reports_recovery() {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buffer = Buffer(Arc::default());
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let route = tunnel_route("192.168.188.1/32");
        let mut state = routing(vec![route]);
        for tick in 0..3 {
            macos_apply_route_plan(
                &mut state,
                vec![],
                tick > 0,
                &|_| {
                    if tick < 2 {
                        anyhow::bail!("temporarily unavailable");
                    }
                    Ok(())
                },
                &|_| panic!("nothing to add"),
                &|_| {},
            );
        }
    });
    let log = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    let failures: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("userspace_helper_reconcile_route_delete_failed"))
        .collect();
    assert_eq!(failures.len(), 2, "{log}");
    assert!(failures[0].contains("WARN"), "{log}");
    assert!(failures[1].contains("DEBUG"), "{log}");
    assert!(
        log.lines().any(|line| line.contains("INFO")
            && line.contains("userspace_helper_reconcile_route_retry_succeeded")),
        "{log}"
    );
}
