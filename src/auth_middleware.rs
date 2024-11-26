use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::ErrorUnauthorized;
use actix_web::{Error, HttpMessage};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;
use std::fs;
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthMiddleware {
    decoding_key: Arc<DecodingKey>,
}

#[derive(Clone, Debug)]
pub struct AuthenticationInfo {
    pub username: Arc<String>,
}

impl AuthMiddleware {
    pub fn new(token_file: &str) -> Self {
        let file_content = fs::read_to_string(token_file).expect("Failed to read token file");
        let decoding_key = DecodingKey::from_rsa_pem(file_content.as_bytes())
            .expect("Failed to use provided public key for JWTs");
        AuthMiddleware {
            decoding_key: Arc::new(decoding_key),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareService {
            service,
            decoding_key: Arc::clone(&self.decoding_key),
        })
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
    decoding_key: Arc<DecodingKey>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let len = "bearer ".len();
        let user_id: Option<String> = req
            .headers()
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .and_then(|hv| Some(&hv[len..]))
            .and_then(|token| {
                decode::<Claims>(
                    token,
                    self.decoding_key.borrow(),
                    &Validation::new(Algorithm::RS256),
                )
                .ok()
            })
            .and_then(|f| Some(f.claims.sub));

        if let Some(found_user) = user_id {
            println!("Found user: {}", found_user); // TODO: Should be logged or removed
            req.extensions_mut().insert::<AuthenticationInfo>({
                AuthenticationInfo {
                    username: Arc::new(found_user),
                }
            });
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }

        Box::pin(async move { Err(ErrorUnauthorized("Unauthorized")) }) // TODO check actix-extras#260 to give correct CORS headers on error
    }
}
