// use crate::auth_middleware::{AuthenticationInfo, Domains};
// use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
// use actix_web::error::{ErrorForbidden, ErrorUnauthorized};
// use actix_web::{Error, HttpMessage};
// use futures_util::future::{ok, LocalBoxFuture, Ready};
// use serde::Deserialize;
// use std::collections::HashMap;
// use std::fs;
use std::sync::Arc;

use crate::auth_middleware::Domains;

// #[derive(Deserialize)]
// struct DomainConfig {
//     from: HashMap<String, Vec<String>>,
//     to: HashMap<String, Vec<String>>,
// }

// #[derive(Clone)]
// pub struct DomainMiddleware {
//     from: Arc<HashMap<String, Vec<String>>>,
//     to: Arc<HashMap<String, Vec<String>>>,
// }

// impl DomainMiddleware {
//     pub fn new(domain_file: &str) -> Self {
//         let file_content = fs::read_to_string(domain_file).expect("Failed to read domain file");

//         let token_config: DomainConfig =
//             serde_yml::from_str(&file_content).expect("Failed to parse token file");

//         DomainMiddleware {
//             from: Arc::new(token_config.from),
//             to: Arc::new(token_config.to),
//         }
//     }
// }

// impl<S, B> Transform<S, ServiceRequest> for DomainMiddleware
// where
//     S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
//     S::Future: 'static,
//     B: 'static,
// {
//     type Response = ServiceResponse<B>;
//     type Error = Error;
//     type Transform = DomainMiddlewareService<S>;
//     type InitError = ();
//     type Future = Ready<Result<Self::Transform, Self::InitError>>;

//     fn new_transform(&self, service: S) -> Self::Future {
//         ok(DomainMiddlewareService {
//             service,
//             from: Arc::clone(&self.from),
//             to: Arc::clone(&self.to),
//         })
//     }
// }

// pub struct DomainMiddlewareService<S> {
//     service: S,
//     from: Arc<HashMap<String, Vec<String>>>,
//     to: Arc<HashMap<String, Vec<String>>>,
// }

#[derive(Clone, Debug)]
pub struct DomainInfo {
    pub from: Arc<Domains>,
    pub to: Arc<Domains>,
}

// impl<S, B> Service<ServiceRequest> for DomainMiddlewareService<S>
// where
//     S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
//     S::Future: 'static,
//     B: 'static,
// {
//     type Response = ServiceResponse<B>;
//     type Error = Error;
//     type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

//     forward_ready!(service);

//     fn call(&self, req: ServiceRequest) -> Self::Future {
//         // Clone the auth info, and arc references to 'from' and 'to' maps
//         let auth_info = req.extensions().get::<AuthenticationInfo>().cloned();
//         let from_map = Arc::clone(&self.from);
//         let to_map = Arc::clone(&self.to);

//         // Handle case with or without authentication info
//         if let Some(auth_info) = auth_info {
//             let username = auth_info.username.as_str();
//             let user_from_contexts = from_map.get(username);
//             let user_to_contexts = to_map.get(username);

//             if let (Some(from), Some(to)) = (user_from_contexts, user_to_contexts) {
//                 req.extensions_mut().insert(DomainInfo {
//                     from: Arc::new(from.clone()),
//                     to: Arc::new(to.clone()),
//                 });
//                 let fut = self.service.call(req);

//                 Box::pin(async move {
//                     // Reconstruct the request
//                     let res = fut.await?;
//                     Ok(res)
//                 })
//             } else {
//                 Box::pin(async move { Err(ErrorForbidden("User not found in domain allowlist")) })
//             }
//         } else {
//             // No authentication info provided
//             Box::pin(async move { Err(ErrorUnauthorized("No authentication info provided")) })
//         }
//     }
// }
