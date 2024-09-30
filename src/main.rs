mod auth_middleware;
mod application;
mod domain_middleware;
mod redis_connector;
mod pep_system_connector;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use actix_web::middleware::{Logger};
use env_logger::Env;
use crate::application::*;
use crate::auth_middleware::AuthMiddleware;
use crate::domain_middleware::DomainMiddleware;
use crate::redis_connector::RedisConnector;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth_middleware = AuthMiddleware::new("resources/tokens.yml");
    let domain_middleware = DomainMiddleware::new("resources/allowlist.yml");
    let redis_connector = RedisConnector::new().expect("Failed to connect to Redis");
    let pep_system = pep_system_connector::create_pepsystem("resources/server_config.yml");

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    println!("Starting server");
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::default()
                .send_wildcard()
                .allow_any_origin()
                .allowed_methods(vec!["GET", "POST"])
            )
            .wrap(Logger::default())
            .route("/status", web::get().to(status))
            .route("/random", web::get().to(random))
            .service(
                web::scope("")
                    .app_data(web::Data::new(redis_connector.clone()))
                    .app_data(web::Data::new(pep_system.clone()))
                    .wrap(auth_middleware.clone()) // Not needed for random
                    .route("/rekey", web::post().to(rekey)) // TODO
                    .route("/start_session", web::get().to(start_session))
                    .route("/end_session", web::post().to(end_session))
                    .service(
                        web::scope("")
                            .route("/pseudonymize", web::post().to(pseudonymize)
                                .wrap(domain_middleware.clone())
                            ))
            )
    })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
