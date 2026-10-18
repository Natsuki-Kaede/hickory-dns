#![cfg(feature = "__dnssec")]

//! Validation of answers from unsigned zones below an insecure delegation, served by
//! authoritative servers with nonstandard behaviour, and of negative answers at the end of a
//! CNAME chain.
//!
//! The validator wraps a handle that turns negative answers into errors like the recursor's name
//! servers do, and the request handler routes each query to the zone that a recursor would ask:
//! DS queries go to the parent zone.
//!
//! - `example.` is signed (the trust anchor) and delegates `nons.example.` and
//!   `unsigned.example.` without DS records.
//! - `nons.example.` is unsigned and publishes no NS RRset at its apex.
//! - `unsigned.example.` is unsigned and delegates `www.unsigned.example.`, but its servers answer
//!   the DS query for that name with a referral.

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};

use futures::{StreamExt, stream::BoxStream};
use hickory_integration::generate_key;
use hickory_net::{
    DnsError, DnsHandle, NetError,
    client::Client,
    dnssec::DnssecDnsHandle,
    runtime::{Time, TokioRuntimeProvider},
    udp::UdpClientStream,
    xfer::FirstAnswer,
};
use hickory_proto::{
    dnssec::{DnssecSigner, Proof, PublicKeyBuf, SigningKey, TrustAnchors, rdata::DNSKEY},
    op::{
        DnsRequest, DnsRequestOptions, DnsResponse, Header, HeaderCounts, Metadata, Query,
        ResponseCode,
    },
    rr::{
        Name, RData, Record, RecordType, RrKey,
        rdata::{A, CNAME, NS, SOA},
    },
};
use hickory_server::{
    Server,
    dnssec::NxProofKind,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, MessageResponseBuilder, ZoneHandler, ZoneType},
};
use test_support::subscribe;
use tokio::net::UdpSocket;

/// An A record in an unsigned zone without an apex NS RRset is insecure.
#[tokio::test]
async fn zone_without_apex_ns_is_insecure() {
    let fixture = Fixture::new().await;

    let response = fixture
        .lookup("www.nons.example.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(answer_proofs(&response, RecordType::A), [Proof::Insecure]);
}

/// An A record in an unsigned zone whose unsigned parent answers DS queries for it with a
/// referral is insecure.
#[tokio::test]
async fn referral_for_ds_below_insecure_zone_is_insecure() {
    let fixture = Fixture::new().await;

    let response = fixture
        .lookup("www.unsigned.example.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(answer_proofs(&response, RecordType::A), [Proof::Insecure]);
}

/// NODATA from an unsigned zone at the end of a CNAME chain from a signed zone is insecure. The
/// target zone publishes no apex NS RRset, so its SOA has to mark the zone cut.
#[tokio::test]
async fn cname_to_unsigned_nodata_is_insecure() {
    let fixture = Fixture::new().await;

    let response = fixture
        .lookup("alias-unsigned.example.", RecordType::AAAA)
        .await
        .unwrap();
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(answer_proofs(&response, RecordType::CNAME), [Proof::Secure]);
    assert!(
        response
            .authorities
            .iter()
            .all(|record| record.proof == Proof::Insecure),
        "{response:?}"
    );
}

/// NODATA from a signed zone at the end of a CNAME chain is proven for the chain's last name.
#[tokio::test]
async fn cname_to_signed_nodata_is_secure() {
    let fixture = Fixture::new().await;

    let response = fixture
        .lookup("alias-signed.example.", RecordType::AAAA)
        .await
        .unwrap();
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(answer_proofs(&response, RecordType::CNAME), [Proof::Secure]);
}

struct Fixture {
    handle: DnssecDnsHandle<NegativeAsError>,
    _server: Server<Router>,
}

impl Fixture {
    async fn new() -> Self {
        subscribe();

        let (key, public_key) = generate_key();
        let router = Router::new(key);

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let mut server = Server::new(router);
        server.register_socket(socket);

        let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::new()).build();
        let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);

        Self {
            handle: DnssecDnsHandle::with_trust_anchor(
                NegativeAsError(client),
                trust_anchor(&public_key),
            ),
            _server: server,
        }
    }

    async fn lookup(&self, name: &str, record_type: RecordType) -> Result<DnsResponse, NetError> {
        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        options.edns_set_dnssec_ok = true;
        self.handle
            .lookup(Query::query(name.parse().unwrap(), record_type), options)
            .first_answer()
            .await
    }
}

fn trust_anchor(public_key: &PublicKeyBuf) -> Arc<TrustAnchors> {
    let mut trust_anchor = TrustAnchors::empty();
    trust_anchor.insert_with_name(public_key, name("example.").into());
    Arc::new(trust_anchor)
}

fn answer_proofs(response: &DnsResponse, record_type: RecordType) -> Vec<Proof> {
    response
        .answers
        .iter()
        .filter(|record| record.record_type() == record_type)
        .map(|record| record.proof)
        .collect()
}

/// Turns negative answers into errors, like the resolver's name servers.
#[derive(Clone)]
struct NegativeAsError(Client<TokioRuntimeProvider>);

impl DnsHandle for NegativeAsError {
    type Response = BoxStream<'static, Result<DnsResponse, NetError>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        self.0
            .send(request)
            .map(|result| result.and_then(|r| DnsError::from_response(r).map_err(NetError::from)))
            .boxed()
    }
}

/// Answers each query from the zone a recursor would ask, or from a canned response.
struct Router {
    zones: Vec<(Name, Catalog)>,
    canned: HashMap<(Name, RecordType), Canned>,
}

struct Canned {
    answers: Vec<Record>,
    authorities: Vec<Record>,
}

impl Router {
    fn new(key: Box<dyn SigningKey>) -> Self {
        let example = name("example.");
        let nons = name("nons.example.");
        let unsigned = name("unsigned.example.");
        let www_unsigned = name("www.unsigned.example.");

        let mut parent = zone(
            &example,
            vec![
                ns(&example, "ns.example."),
                a("ns.example.", 1),
                ns(&nons, "ns.nons.example."),
                ns(&unsigned, "ns.unsigned.example."),
                a("host.example.", 2),
                cname("alias-signed.example.", "host.example."),
                cname("alias-unsigned.example.", "www.nons.example."),
            ],
        );
        parent
            .add_zone_signing_key_mut(DnssecSigner::new(
                DNSKEY::from_key(&key.to_public_key().unwrap()),
                key,
                example.clone(),
                Duration::from_secs(86400),
            ))
            .unwrap();
        parent.secure_zone_mut().unwrap();

        // NS probes of a zone without an apex NS RRset get NODATA with its SOA.
        let nons_zone = zone(&nons, vec![a("www.nons.example.", 3)]);
        let unsigned_zone = zone(
            &unsigned,
            vec![
                ns(&unsigned, "ns.unsigned.example."),
                ns(&www_unsigned, "ns.www.unsigned.example."),
            ],
        );
        let www_zone = zone(
            &www_unsigned,
            vec![
                ns(&www_unsigned, "ns.www.unsigned.example."),
                a("www.unsigned.example.", 4),
            ],
        );

        // Recursors combine a CNAME with the negative answer for its target.
        let signed = |parent: &mut InMemoryZoneHandler, name: &Name, record_type| {
            parent.records_get_mut()[&RrKey::new(name.into(), record_type)]
                .records_with_rrsigs()
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut canned = HashMap::new();
        canned.insert(
            (name("alias-signed.example."), RecordType::AAAA),
            Canned {
                answers: signed(
                    &mut parent,
                    &name("alias-signed.example."),
                    RecordType::CNAME,
                ),
                authorities: [
                    signed(&mut parent, &name("host.example."), RecordType::NSEC),
                    signed(&mut parent, &example, RecordType::SOA),
                ]
                .concat(),
            },
        );
        canned.insert(
            (name("alias-unsigned.example."), RecordType::AAAA),
            Canned {
                answers: signed(
                    &mut parent,
                    &name("alias-unsigned.example."),
                    RecordType::CNAME,
                ),
                authorities: vec![soa(&nons)],
            },
        );
        // The unsigned parent answers the DS query for its delegated child with a referral.
        canned.insert(
            (www_unsigned.clone(), RecordType::DS),
            Canned {
                answers: vec![],
                authorities: vec![ns(&www_unsigned, "ns.www.unsigned.example.")],
            },
        );

        Self {
            zones: vec![
                (example, catalog(parent)),
                (nons, catalog(nons_zone)),
                (unsigned, catalog(unsigned_zone)),
                (www_unsigned, catalog(www_zone)),
            ],
            canned,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Router {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query = request.request_info().unwrap().query;
        let qname = Name::from(query.name());
        let qtype = query.query_type();

        if let Some(canned) = self.canned.get(&(qname.clone(), qtype)) {
            let mut metadata = Metadata::response_from_request(&request.metadata);
            metadata.response_code = ResponseCode::NoError;
            let mut builder = MessageResponseBuilder::from_message_request(request);
            if let Some(edns) = &request.edns {
                builder.edns(edns);
            }
            let response = builder.build(metadata, &canned.answers, &canned.authorities, [], []);
            return match response_handle.send_response(response).await {
                Ok(info) => info,
                Err(_) => ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                }),
            };
        }

        // DS RRsets are served by the parent zone.
        let served = match qtype {
            RecordType::DS if qname.num_labels() > 1 => qname.base_name(),
            _ => qname,
        };
        let (_, catalog) = self
            .zones
            .iter()
            .filter(|(origin, _)| origin.zone_of(&served))
            .max_by_key(|(origin, _)| origin.num_labels())
            // There is no root zone; `example.` answers its own DS query.
            .unwrap_or(&self.zones[0]);
        catalog
            .handle_request::<R, T>(request, response_handle)
            .await
    }
}

fn zone(origin: &Name, records: Vec<Record>) -> InMemoryZoneHandler {
    let mut zone = InMemoryZoneHandler::empty(
        origin.clone(),
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(NxProofKind::Nsec),
    );
    for record in [soa(origin)].into_iter().chain(records) {
        zone.upsert_mut(record, 0);
    }
    zone
}

fn catalog(zone: InMemoryZoneHandler) -> Catalog {
    let mut catalog = Catalog::new();
    catalog.upsert(zone.origin().clone(), vec![Arc::new(zone)]);
    catalog
}

fn name(name: &str) -> Name {
    Name::from_ascii(name).unwrap()
}

fn soa(origin: &Name) -> Record {
    let mname = Name::from_ascii("ns")
        .unwrap()
        .append_domain(origin)
        .unwrap();
    let rname = Name::from_ascii("hostmaster")
        .unwrap()
        .append_domain(origin)
        .unwrap();
    Record::from_rdata(
        origin.clone(),
        3600,
        RData::SOA(SOA::new(mname, rname, 1, 3600, 300, 3600000, 3600)),
    )
}

fn ns(owner: &Name, target: &str) -> Record {
    Record::from_rdata(owner.clone(), 3600, RData::NS(NS(name(target))))
}

fn a(owner: &str, host: u8) -> Record {
    Record::from_rdata(
        name(owner),
        3600,
        RData::A(A(Ipv4Addr::new(192, 0, 2, host))),
    )
}

fn cname(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 3600, RData::CNAME(CNAME(name(target))))
}
