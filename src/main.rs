
use actix_web::http::header::ContentType;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, guard, web, middleware::Logger};
use futures::StreamExt;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde_json::{Value, json};
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

extern crate clap;
use clap::{AppSettings, Clap};

#[derive(Clone, Clap, Deserialize, Debug)]
#[clap(name="apnsmock", version="0.1", author="Cibin George <cibin@getblueshift.com>")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Config {
    #[clap(
        short='a',
        long,
        default_value="127.0.0.1:8443",
        about = "network address to serve on"
    )]
    address: String,

    #[clap(
        short='y',
        long,
        about = "if allok is true, server will respond with 200 status to all requests"
    )]
    all_ok: bool,

    #[clap(
        long,
        about = "if json_success is true, server will respond {success: true} for successful requests"
    )]
    json_success: bool,


    #[clap(
        short='c',
        long,
        default_value="5",
        about = "maximum number of concurrent HTTP/2 connections"
    )]
    max_connections: u64,

    #[clap(
        short='s',
        long="streams",
        default_value="500",
        about = "number of concurrent HTTP/2 streams"
    )]
    max_concurrent_streams: u64,

    #[clap(
        short='d',
        long,
        default_value="100",
        about = "amount of time by which client connect attempts should be delayed"
    )]
    connection_delay: u64,

    #[clap(
        short,
        long="resp-delay",
        default_value="5",
        about = "amount of time by which responses should be delayed"
    )]
    response_delay: u64,

    #[clap(
        short='x',
        long,
        default_value="certs/server.crt",
        about = "path to server TLS certificate"
    )]
    cert: String,

    #[clap(
        short='k',
        long,
        default_value="certs/key.crt",
        about = "path to TLS certificate key"
    )]
    key: String,

    #[clap(
        short='t',
        long,
        about = "use token based authentication"
    )]
    token_auth: bool,
}


#[derive(Error, Debug)]
pub enum ApnsMockError {
    #[error("BadCollapseId")]
    BadCollapseId(String),
    #[error("BadDeviceToken")]
    BadDeviceToken(String),
    #[error("BadExpirationDate")]
    BadExpirationDate(String),
    #[error("BadMessageId")]
    BadMessageId(String),
    #[error("BadPriority")]
    BadPriority(String),
    #[error("BadTopic")]
    BadTopic(String),
    #[error("DeviceTokenNotForTopic")]
    DeviceTokenNotForTopic(String),
    #[error("DuplicateHeaders")]
    DuplicateHeaders(String),
    #[error("IdleTimeout")]
    IdleTimeout(String),
    #[error("InvalidPushType")]
    InvalidPushType(String),
    #[error("MissingDeviceToken")]
    MissingDeviceToken(String),
    #[error("MissingTopic")]
    MissingTopic(String),
    #[error("PayloadEmpty")]
    PayloadEmpty(String),
    #[error("TopicDisallowed")]
    TopicDisallowed(String),
    #[error("BadCertificate")]
    BadCertificate(String),
    #[error("BadCertificateEnvironment")]
    BadCertificateEnvironment(String),
    #[error("ExpiredProviderToken")]
    ExpiredProviderToken(String),
    #[error("Forbidden")]
    Forbidden(String),
    #[error("InvalidProviderToken")]
    InvalidProviderToken(String),
    #[error("MissingProviderToken")]
    MissingProviderToken(String),
    #[error("BadPath")]
    BadPath(String),
    #[error("MethodNotAllowed")]
    MethodNotAllowed(String),
    #[error("Unregistered")]
    Unregistered(String),
    #[error("InvalidPayload")]
    InvalidPayload(String),
    #[error("PayloadNotJson")]
    PayloadNotJson(String),
    #[error("PayloadTooLarge")]
    PayloadTooLarge(String),
    #[error("TooManyProviderTokenUpdates")]
    TooManyProviderTokenUpdates(String),
    #[error("TooManyRequests")]
    TooManyRequests(String),
    #[error("InternalServerError")]
    InternalServerError(String),
    #[error("ServiceUnavailable")]
    ServiceUnavailable(String),
    #[error("Shutdown")]
    Shutdown(String),
}

impl ApnsMockError {
    pub  fn apns_id(&self) -> &str {
        match &self {
            ApnsMockError::BadCollapseId(id) => id.as_str(),
            ApnsMockError::BadDeviceToken(id) => id.as_str(),
            ApnsMockError::BadExpirationDate(id) => id.as_str(),
            ApnsMockError::BadMessageId(id) => id.as_str(),
            ApnsMockError::BadPriority(id) => id.as_str(),
            ApnsMockError::BadTopic(id) => id.as_str(),
            ApnsMockError::DeviceTokenNotForTopic(id) => id.as_str(),
            ApnsMockError::DuplicateHeaders(id) => id.as_str(),
            ApnsMockError::IdleTimeout(id) => id.as_str(),
            ApnsMockError::InvalidPushType(id) => id.as_str(),
            ApnsMockError::MissingDeviceToken(id) => id.as_str(),
            ApnsMockError::MissingTopic(id) => id.as_str(),
            ApnsMockError::PayloadEmpty(id) => id.as_str(),
            ApnsMockError::TopicDisallowed(id) => id.as_str(),
            ApnsMockError::BadCertificate(id) => id.as_str(),
            ApnsMockError::BadCertificateEnvironment(id) => id.as_str(),
            ApnsMockError::ExpiredProviderToken(id) => id.as_str(),
            ApnsMockError::Forbidden(id) => id.as_str(),
            ApnsMockError::InvalidProviderToken(id) => id.as_str(),
            ApnsMockError::MissingProviderToken(id) => id.as_str(),
            ApnsMockError::BadPath(id) => id.as_str(),
            ApnsMockError::MethodNotAllowed(id) => id.as_str(),
            ApnsMockError::Unregistered(id) => id.as_str(),
            ApnsMockError::InvalidPayload(id) => id.as_str(),
            ApnsMockError::PayloadNotJson(id) => id.as_str(),
            ApnsMockError::PayloadTooLarge(id) => id.as_str(),
            ApnsMockError::TooManyProviderTokenUpdates(id) => id.as_str(),
            ApnsMockError::TooManyRequests(id) => id.as_str(),
            ApnsMockError::InternalServerError(id) => id.as_str(),
            ApnsMockError::ServiceUnavailable(id) => id.as_str(),
            ApnsMockError::Shutdown(id) => id.as_str(),
        }
    }
}
impl actix_web::ResponseError for ApnsMockError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        let http_response_code: u16 = match &self {
            ApnsMockError::BadCollapseId(_) => 400,
            ApnsMockError::BadDeviceToken(_) => 400,
            ApnsMockError::BadExpirationDate(_) => 400,
            ApnsMockError::BadMessageId(_) => 400,
            ApnsMockError::BadPriority(_) => 400,
            ApnsMockError::BadTopic(_) => 400,
            ApnsMockError::DeviceTokenNotForTopic(_) => 400,
            ApnsMockError::DuplicateHeaders(_) => 400,
            ApnsMockError::IdleTimeout(_) => 400,
            ApnsMockError::InvalidPushType(_) => 400,
            ApnsMockError::MissingDeviceToken(_) => 400,
            ApnsMockError::MissingTopic(_) => 400,
            ApnsMockError::PayloadEmpty(_) => 400,
            ApnsMockError::TopicDisallowed(_) => 400,
            ApnsMockError::BadCertificate(_) => 403,
            ApnsMockError::BadCertificateEnvironment(_) => 403,
            ApnsMockError::ExpiredProviderToken(_) => 403,
            ApnsMockError::Forbidden(_) => 403,
            ApnsMockError::InvalidProviderToken(_) => 403,
            ApnsMockError::MissingProviderToken(_) => 403,
            ApnsMockError::BadPath(_) => 404,
            ApnsMockError::MethodNotAllowed(_) => 405,
            ApnsMockError::Unregistered(_) => 410,
            ApnsMockError::InvalidPayload(_) => 400,
            ApnsMockError::PayloadNotJson(_) => 400,
            ApnsMockError::PayloadTooLarge(_) => 413,
            ApnsMockError::TooManyProviderTokenUpdates(_) => 429,
            ApnsMockError::TooManyRequests(_) => 429,
            ApnsMockError::InternalServerError(_) => 500,
            ApnsMockError::ServiceUnavailable(_) => 503,
            ApnsMockError::Shutdown(_) => 503,
        };
        actix_web::http::StatusCode::from_u16(http_response_code).unwrap()
    }

    fn error_response(&self) -> HttpResponse {
        let  apns_id = self.apns_id();
        let  status_code = self.status_code();
        let mut response = HttpResponse::build(status_code);
        response.insert_header(ContentType::json());
        response.insert_header(("apns-id", apns_id));

        let payload = if status_code.as_u16() == 410 {
            let now = chrono::offset::Utc::now().timestamp_millis();
            json!({
                "reason": format!("{}", &self),
                "timestamp": now,
            })
        } else {
            json!({
                "reason": format!("{}", &self),
            })
        };
        response.body(payload)
    }
}

use regex::Regex;
use once_cell::sync::OnceCell;

fn validate_device_token(token: &str) -> bool {
    static RE: OnceCell<Regex> = OnceCell::new();
    let compiled_re = RE.get_or_init(|| {
        Regex::new("[[:xdigit:]]+").unwrap()
    });

    compiled_re.is_match(token)
}

#[derive(Clone, Deserialize, Debug)]
struct  AuthTokenHeaders{
    alg: String,
    kid: String,
}

#[derive(Clone, Deserialize, Debug)]
struct  AuthTokenBody{
    iss: String,
    iat: i64,
}


const MAX_SIZE: usize = 1_048_576; // max payload size is 1Mb


// params=Json: Object({"aps": Object({"alert": String("hi, Rajesh"), "sound": String("default")})}) request=
// HttpRequest HTTP/2.0 POST:/3/device/9d36a62ffccd017133e5766f48f235d546c5bd445a04c4aa96bea4f43fa49176
//   params: Path { path: Url { uri: https://localhost:9443/3/device/9d36a62ffccd017133e5766f48f235d546c5bd445a04c4aa96bea4f43fa49176, path: None }, skip: 74, segments: [("device_token", Segment(10, 74))] }
//   headers:
//     "user-agent": "mint/1.3.0"
//     "content-length": "48"
//     "content-type": "application/json"
//     "apns-expiration": "0"
//     "apns-push-type": "alert"
//     "apns-topic": "com.blueshift.reads"
//     "apns-id": "5a4292ba-dea6-4961-8cef-3cdb74507027"
//     "apns-priority": "10"
async fn push_handler(config: web::Data<Config>, req: HttpRequest, mut payload: web::Payload, device_token_param: web::Path<(String,)>) ->  actix_web::Result<HttpResponse, ApnsMockError> {
    let headers = req.headers();
    let device_token = device_token_param.0.as_str();

    let  apns_id = headers.get("apns-id");
    if apns_id.is_none() {
        let uuid_v4 = Uuid::new_v4().to_hyphenated().to_string();
        if config.all_ok {
            return Ok(generate_success_response(config, uuid_v4))
        }
        return  Err(ApnsMockError::BadMessageId(uuid_v4))
    }
    let apns_id = apns_id.unwrap().to_str().unwrap().to_owned();

    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| ApnsMockError::InvalidPayload(apns_id.clone()))?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
            return  Err(ApnsMockError::PayloadTooLarge(apns_id))
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty()  {
        return  Err(ApnsMockError::PayloadEmpty(apns_id))
    }

    let params = serde_json::from_slice::<Value>(&body).map_err(|_| ApnsMockError::PayloadNotJson(apns_id.clone()))?;
    if config.all_ok {
        return Ok(generate_success_response(config, apns_id))
    }

    if Uuid::parse_str(&apns_id).is_err() {
        return  Err(ApnsMockError::BadMessageId(apns_id))
    }

    if !validate_device_token(device_token) {
        return  Err(ApnsMockError::BadDeviceToken(apns_id))
    }

    let now = chrono::offset::Utc::now().timestamp();
    let  authorization_hdr = headers.get("authorization");
    if let Some(auth) = authorization_hdr {
        let authorization = auth.to_str().unwrap();
        if !authorization.starts_with("bearer "){
            return  Err(ApnsMockError::MissingProviderToken(apns_id))
        }
        let auth_token = authorization.strip_prefix("bearer ").unwrap();
        if auth_token.is_empty() {
            return  Err(ApnsMockError::InvalidProviderToken(apns_id))
        }
        let split: Vec<&str> = auth_token.split('.').collect();
        if split.len() != 3 {
            return  Err(ApnsMockError::InvalidProviderToken(apns_id))
        }
        let token_header_vec= base64::decode(split[0]).map_err(|_| ApnsMockError::InvalidProviderToken(apns_id.clone()))?;
        let token_headers  = serde_json::from_slice::<AuthTokenHeaders>(&token_header_vec).map_err(|_| ApnsMockError::InvalidProviderToken(apns_id.clone()))?;
        if token_headers.alg != "ES256" || token_headers.kid.len() != 10 {
            return  Err(ApnsMockError::InvalidProviderToken(apns_id))
        }

        let token_body_vec= base64::decode(split[1]).map_err(|_| ApnsMockError::InvalidProviderToken(apns_id.clone()))?;
        let token_body  = serde_json::from_slice::<AuthTokenBody>(&token_body_vec).map_err(|_| ApnsMockError::InvalidProviderToken(apns_id.clone()))?;

        if token_body.iss.len() != 10 || (token_body.iat < now - 3600) || (token_body.iat > now + 3600) {
            return  Err(ApnsMockError::ExpiredProviderToken(apns_id))
        }

        //  Team IDs (JWT "iss" claims) starting with '1' return 403, "InvalidProviderToken"
        if token_body.iss.starts_with('1') { // Feature  for testing
            return  Err(ApnsMockError::InvalidProviderToken(apns_id))
        }
    } else if config.token_auth {
        return  Err(ApnsMockError::MissingProviderToken(apns_id))
    }

    let  apns_priority_val = headers.get("apns-priority");
    if apns_priority_val.is_none() {
        return Err(ApnsMockError::BadPriority(apns_id))
    }
    let apns_priority = apns_priority_val.unwrap().to_str().unwrap();
    if apns_priority.is_empty() || !(apns_priority == "5" || apns_priority == "10") {
        return Err(ApnsMockError::BadPriority(apns_id))
    }

    let  topic_val = headers.get("apns-topic");
    if topic_val.is_none() {
        return Err(ApnsMockError::MissingTopic(apns_id))
    }
    let topic_str = topic_val.unwrap().to_str().map_err(|_| ApnsMockError::MissingTopic(apns_id.clone()))?;
    if topic_str.is_empty() {
        return Err(ApnsMockError::MissingTopic(apns_id))
    }

    let  expiration_val = headers.get("apns-expiration");
    if expiration_val.is_none() {
        return Err(ApnsMockError::BadExpirationDate(apns_id))
    }
    let expiration_str = expiration_val.unwrap().to_str().map_err(|_| ApnsMockError::BadExpirationDate(apns_id.clone()))?;
    let expiration_timestamp = expiration_str.parse::<i64>().map_err(|_| ApnsMockError::BadExpirationDate(apns_id.clone()))?;
    if expiration_timestamp < 0 || (expiration_timestamp  != 0 && expiration_timestamp < now) {
        return Err(ApnsMockError::BadExpirationDate(apns_id));
    }

    /*
    Preconfigured failure scenarios
        The following scenarios produce mock rejection responses:

        Device tokens starting with '1' return 400, "BadDeviceToken"
        Device tokens starting with '2' return 410, "Unregistered"
        Device tokens starting with the same letter/digit as APNS topic return 400, "DeviceTokenNotForTopic"
        Topics starting with 'd' return 400, "TopicDisallowed"
        Team IDs (JWT "iss" claims) starting with '1' return 403, "InvalidProviderToken"
     */

    if device_token.starts_with('1') {
        return Err(ApnsMockError::BadDeviceToken(apns_id))
    }
    if device_token.starts_with('2') {
        return Err(ApnsMockError::Unregistered(apns_id))
    }

    let token_first_char = device_token.chars().next().unwrap();
    let topic_first_char = topic_str.chars().next().unwrap();
    if token_first_char == topic_first_char {
        return Err(ApnsMockError::DeviceTokenNotForTopic(apns_id))
    }

    if topic_str.starts_with('d') {
        return Err(ApnsMockError::TopicDisallowed(apns_id))
    }

    Ok(generate_success_response(config, apns_id))
}

fn generate_success_response(config: web::Data<Config>, apns_id: String) ->  HttpResponse {
    let mut builder = HttpResponse::Ok();
    builder.insert_header(ContentType::json())
           .insert_header(("apns-id", apns_id.as_str()));

    if config.json_success {
        let response = json!({
            "success": true,
        });
        builder.body(response)
    } else {
        builder.finish()
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let config: Config = Config::parse();
    println!("Got config={:?}", &config);

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    // load ssl keys
    // to create a self-signed temporary cert for testing:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'`
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(&config.key, SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file(&config.cert).unwrap();

    let  address =  config.address.clone();
    HttpServer::new(move || App::new()
                                    .data(config.clone())
                                    .wrap(Logger::new("%a %{User-Agent}i"))
                                    //.route("/3/device/{device_token}", web::post().to(push_handler)))
                                    .service(
                                        web::resource("/3/device/{device_token}")
                                            .guard(guard::Header("content-type", "application/json"))
                                            .route(web::post().to(push_handler))
                                            .route(web::route().to(HttpResponse::MethodNotAllowed)),
                                    ))
        .bind_openssl(&address, builder)?
        .workers(4)
        .max_connections(5)
        .run()
        .await
}