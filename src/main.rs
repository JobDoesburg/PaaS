mod application;
mod auth_middleware;
mod pep_crypto;
mod pseudo_domain_middleware;
mod redis_connector;

use crate::application::*;
use crate::auth_middleware::AuthMiddleware;
use crate::pseudo_domain_middleware::DomainMiddleware;
use crate::redis_connector::RedisConnector;
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{http::header, web, App, HttpServer};
use env_logger::Env; // Import for header configuration

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth_middleware = AuthMiddleware::new("resources/public.pem");
    let domain_middleware = DomainMiddleware::new("resources/allowlist.yml");
    let redis_connector = RedisConnector::new().expect("Failed to connect to Redis");
    let pep_system = pep_crypto::create_pep_crypto_system("resources/server_config.yml");

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    println!("Starting server");
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .wrap(Logger::default())
            .route("/status", web::get().to(status))
            .route("/random", web::get().to(random))
            .service(
                web::scope("")
                    .app_data(web::Data::new(redis_connector.clone()))
                    .app_data(web::Data::new(pep_system.clone()))
                    .wrap(auth_middleware.clone()) // Not needed for random
                    .route("/start_session", web::post().to(start_session))
                    .route("/end_session", web::post().to(end_session))
                    .route("/get_sessions", web::get().to(get_all_sessions))
                    .route("/get_sessions/{username}", web::get().to(get_sessions))
                    .service(web::scope("").route(
                        "/pseudonymize",
                        web::post().to(pseudonymize).wrap(domain_middleware.clone()),
                    ))
                    .service(web::scope("").route(
                        "/rekey",
                        web::post().to(rekey).wrap(domain_middleware.clone()),
                    )),
            )
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
