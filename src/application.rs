use crate::auth_middleware::AuthenticationInfo;
use crate::pseudo_domain_middleware::DomainInfo;
use crate::redis_connector::RedisConnector;
use actix_web::web::{Bytes, Data};
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use libpep::distributed::key_blinding::SessionKeyShare;
use libpep::distributed::systems::PEPSystem;
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationContext};
use libpep::high_level::data_types::{Encrypted, EncryptedPseudonym};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct EncryptedPseudonymResponse {
    encrypted_pseudonym: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PseudonymizationRequest {
    encrypted_pseudonym: String,
    pseudonym_context_from: PseudonymizationContext,
    pseudonym_context_to: PseudonymizationContext,
    enc_context: EncryptionContext,
    dec_context: EncryptionContext,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EndSessionRequest {
    session_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetSessionsRequest {
    username: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct StartSessionResponse {
    session_id: String,
    key_share: SessionKeyShare,
}

#[derive(Serialize, Deserialize)]
pub struct StatusResponse {
    system_id: String,
    timestamp: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetSessionResponse {
    sessions: Vec<String>,
}

pub async fn status() -> impl Responder {
    let system_id = env::var("HOSTNAME").unwrap();

    HttpResponse::Ok().json(StatusResponse {
        system_id,
        timestamp: chrono::offset::Local::now().to_string(),
    })
}

fn has_access_to_context(
    from: Arc<Vec<String>>,
    to: Arc<Vec<String>>,
    pseudonym_context_from: PseudonymizationContext,
    pseudonym_context_to: PseudonymizationContext,
    dec_context: EncryptionContext,
    user_sessions: Vec<String>,
) -> bool {
    // Access control alleen bij de prefix en niet postfix. Voor nu postfix loggen.
    // dec_context moet gelijk zijn aan jouw sessie.
    user_sessions.contains(&dec_context)
        && from.contains(&pseudonym_context_from)
        && to.contains(&pseudonym_context_to)
}

pub async fn pseudonymize_to(
    req: HttpRequest,
    body: Bytes,
    redis: Data<RedisConnector>,
    pep_system: Data<PEPSystem>,
) -> impl Responder {
    pseudonymize(req, body, redis, pep_system, false).await
}

pub async fn pseudonymize_from(
    req: HttpRequest,
    body: Bytes,
    redis: Data<RedisConnector>,
    pep_system: Data<PEPSystem>,
) -> impl Responder {
    pseudonymize(req, body, redis, pep_system, true).await
}

async fn pseudonymize(
    req: HttpRequest,
    body: Bytes,
    redis: Data<RedisConnector>,
    pep_system: Data<PEPSystem>,
    from: bool,
) -> impl Responder {
    let auth = req
        .extensions()
        .get::<AuthenticationInfo>()
        .unwrap()
        .clone();
    let domain_info = req.extensions().get::<DomainInfo>().unwrap().clone();
    let item = serde_json::from_slice::<PseudonymizationRequest>(&body);

    let request = item.unwrap();

    let mut redis_connector = redis.get_ref().clone();
    let sessions = redis_connector
        .get_sessions_for_user(auth.username.to_string())
        .expect("Failed to get sessions");

    if !(has_access_to_context(
        domain_info.from,
        domain_info.to,
        request.pseudonym_context_from.clone(),
        request.pseudonym_context_to.clone(),
        if from {
            request.dec_context.clone()
        } else {
            request.enc_context.clone()
        },
        sessions,
    )) {
        return HttpResponse::Forbidden().body("Domain not allowed");
    }

    let msg_in = EncryptedPseudonym::from_base64(&request.encrypted_pseudonym);
    if msg_in.is_none() {
        return HttpResponse::BadRequest().body("Invalid input");
    }
    let msg_out = pep_system.pseudonymize(
        &msg_in.unwrap(),
        &pep_system.pseudonymization_info(
            &request.pseudonym_context_from,
            &request.pseudonym_context_to,
            &request.enc_context,
            &request.dec_context,
        ),
    );

    HttpResponse::Ok().json(EncryptedPseudonymResponse {
        encrypted_pseudonym: msg_out.encode_to_base64(),
    })
}

pub async fn rekey() -> impl Responder {
    HttpResponse::Ok().body("Rekey")
}

pub async fn start_session(
    req: HttpRequest,
    redis: Data<RedisConnector>,
    pep_system: Data<PEPSystem>,
) -> impl Responder {
    let auth = req
        .extensions()
        .get::<AuthenticationInfo>()
        .unwrap()
        .clone();
    let mut redis_connector = redis.get_ref().clone();

    let session_id = redis_connector
        .start_session(auth.username.to_string())
        .unwrap();

    let key_share = pep_system.session_key_share(&EncryptionContext::from(&session_id.clone()));

    HttpResponse::Ok().json(StartSessionResponse {
        session_id,
        key_share,
    })
}

pub async fn end_session(
    item: web::Json<EndSessionRequest>,
    req: HttpRequest,
    data: Data<RedisConnector>,
) -> impl Responder {
    let auth = req
        .extensions()
        .get::<AuthenticationInfo>()
        .unwrap()
        .clone();
    let session_id = item.session_id.clone();
    let username_in_session = session_id.split('_').next().unwrap();
    let mut redis_connector = data.get_ref().clone();

    if auth.username.as_str() != username_in_session {
        return HttpResponse::Forbidden().body("Session not owned by user");
    }

    redis_connector
        .end_session(auth.username.to_string(), session_id)
        .unwrap();

    HttpResponse::Ok().json({})
}

pub async fn get_sessions(
    path: web::Path<GetSessionsRequest>,
    data: Data<RedisConnector>,
) -> impl Responder {
    let mut redis_connector = data.get_ref().clone();

    let sessions = redis_connector
        .get_sessions_for_user(path.username.clone().unwrap())
        .unwrap();
    HttpResponse::Ok().json(GetSessionResponse { sessions })
}

pub async fn get_all_sessions(data: Data<RedisConnector>) -> impl Responder {
    let mut redis_connector = data.get_ref().clone();

    let sessions = redis_connector.get_all_sessions().unwrap();
    HttpResponse::Ok().json(GetSessionResponse { sessions })
}
