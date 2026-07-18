//! Dependency-acceptance tests for the approved socket2 call surface.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

fn bind_socket(
    domain: Domain,
    socket_type: Type,
    protocol: Protocol,
    address: SocketAddr,
    reuse_address: Option<bool>,
    only_v6: Option<bool>,
) -> Socket {
    let socket = Socket::new(domain, socket_type, Some(protocol))
        .expect("the native platform must create a probe socket");
    if let Some(reuse_address) = reuse_address {
        socket
            .set_reuse_address(reuse_address)
            .expect("the native platform must support reuse-address configuration");
    }
    if let Some(only_v6) = only_v6 {
        socket
            .set_only_v6(only_v6)
            .expect("the native platform must support IPv6 mode configuration");
    }
    socket
        .bind(&SockAddr::from(address))
        .expect("the native platform must bind an ephemeral loopback endpoint");
    socket
}

fn bind_drop_and_rebind(
    domain: Domain,
    socket_type: Type,
    protocol: Protocol,
    address: SocketAddr,
    reuse_address: Option<bool>,
    only_v6: Option<bool>,
) {
    let socket = bind_socket(
        domain,
        socket_type,
        protocol,
        address,
        reuse_address,
        only_v6,
    );
    let bound_address = socket
        .local_addr()
        .expect("the native platform must report the bound endpoint")
        .as_socket()
        .expect("the bound internet socket must return an internet address");
    drop(socket);

    let rebound = bind_socket(
        domain,
        socket_type,
        protocol,
        bound_address,
        reuse_address,
        only_v6,
    );
    drop(rebound);
}

#[test]
fn approved_ipv4_socket_surface_binds_and_releases() {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    for (socket_type, protocol) in [(Type::STREAM, Protocol::TCP), (Type::DGRAM, Protocol::UDP)] {
        bind_drop_and_rebind(
            Domain::IPV4,
            socket_type,
            protocol,
            address,
            Some(false),
            None,
        );
    }
}

#[test]
fn approved_ipv6_socket_surface_binds_and_releases() {
    let address = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    for (socket_type, protocol) in [(Type::STREAM, Protocol::TCP), (Type::DGRAM, Protocol::UDP)] {
        bind_drop_and_rebind(
            Domain::IPV6,
            socket_type,
            protocol,
            address,
            Some(false),
            Some(true),
        );
    }
}

#[test]
fn approved_default_and_reuse_enabled_modes_bind_and_release() {
    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    bind_drop_and_rebind(
        Domain::IPV4,
        Type::STREAM,
        Protocol::TCP,
        address,
        None,
        None,
    );
    bind_drop_and_rebind(
        Domain::IPV4,
        Type::DGRAM,
        Protocol::UDP,
        address,
        Some(true),
        None,
    );
}

#[test]
fn approved_ipv6_dual_stack_wildcard_mode_binds_and_releases() {
    let address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    bind_drop_and_rebind(
        Domain::IPV6,
        Type::STREAM,
        Protocol::TCP,
        address,
        Some(false),
        Some(false),
    );
    bind_drop_and_rebind(
        Domain::IPV6,
        Type::DGRAM,
        Protocol::UDP,
        address,
        Some(true),
        Some(false),
    );
}
