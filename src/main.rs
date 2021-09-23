#![feature(proc_macro_hygiene, decl_macro)]
use std::time::{SystemTime, UNIX_EPOCH};

#[macro_use] extern crate rocket;
use rocket::State;
use rocket::request::{Request, Outcome, FromRequest};
use rocket::http::{Method, Status};
use rocket_cors::{AllowedHeaders, AllowedOrigins, Guard, Responder};

extern crate frank_jwt;
#[macro_use] extern crate serde_json;
use frank_jwt::{Algorithm, encode, decode, ValidationOptions};

extern crate base64;

use random_color::RandomColor;

#[derive(Debug, Clone)]
struct Secrets {
    client_id: String,
    owner_id: String,
    secret: String
}

struct ApiKey {
    secret: Secrets,
    channel_id: String,
    colour: String
}

#[derive(Debug)]
enum ApiKeyError {
    BadCount,
    Missing,
    Invalid,
}

fn is_valid(token: &str, secret: &Secrets, api: &mut ApiKey) -> bool {
    let bearer = token.split(" ").last().unwrap();
    let base64_secret = base64::decode(&secret.secret).unwrap();

    let result = decode(&bearer,
        &base64_secret,
        Algorithm::HS256,
        &ValidationOptions::default());
    
    if result.is_err() { eprintln!("{:?}", result.err()); return false; }
    
    let (_header, payload) = result.unwrap();

    let to_strip = String::from('"');
    let channel_id = payload["channel_id"].to_string().chars().filter(|&c| !to_strip.contains(c)).collect();

    api.channel_id = channel_id;
    api.colour = RandomColor::new().to_hex();
    
    true
}

impl<'a, 'r> FromRequest<'a, 'r> for ApiKey {
    type Error = ApiKeyError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        let secrets = request.guard::<State<Secrets>>().unwrap();
        let mut api_key = ApiKey { secret: secrets.clone(), channel_id: String::from(""), colour: String::from("") };
        
        match keys.len() {
            0 => Outcome::Failure((Status::BadRequest, ApiKeyError::Missing)),
            1 if is_valid(keys[0], &secrets, &mut api_key) => Outcome::Success(api_key),
            1 => Outcome::Failure((Status::BadRequest, ApiKeyError::Invalid)),
            _ => Outcome::Failure((Status::BadRequest, ApiKeyError::BadCount)),
        }
    }
}

fn broadcast_colour_change(channel_id: String, colour: String, secret: &Secrets) {
    let expiry = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 600;
    // create jwt
    let header = json!({});
    let payload = json!({
        "exp": expiry,
        "channel_id": channel_id,
        "user_id": secret.owner_id,
        "role": "external",
        "pubsub_perms": {
            "send": ['*']
        }
    });
    let secret_base64 = base64::decode(&secret.secret).unwrap();
    let jwt = encode(header, &secret_base64, &payload, Algorithm::HS256);

    if jwt.is_err() {
        println!("Error creating jwt: {:?}", jwt);
        return;
    }

    // put into payload
    let token = format!("Bearer {}", jwt.unwrap());

    let response = ureq::post(
        format!("https://api.twitch.tv/extensions/message/{}", channel_id).as_str())
        .set("Authorization", token.as_str())
        .set("Client-Id", secret.client_id.as_str())
        .set("Content-Type", "application/json")
        .send_json(json!({ "content_type": "application/json", "message": colour, "targets": ["broadcast"]}));
    
    if ! response.ok() {
        println!("{:?}", response);
    } 
}

#[get("/")]
fn index() -> &'static str {
    "https://twitch.tv/ko2fan"
}

#[get("/color/query")]
fn query_colour(cors: Guard<'_>, _api_key: ApiKey) -> Responder<&str> {
    cors.responder("#6441a4")
}

#[options("/color/query")]
fn option_query_colour(cors: Guard<'_>) -> Responder<&str> {
    cors.responder("Manual OPTIONS preflight handling")
}

#[post("/color/cycle")]
fn cycle_colour(cors: Guard<'_>, api_key: ApiKey) -> Responder<String> {
    broadcast_colour_change(api_key.channel_id,api_key.colour.clone(), &api_key.secret);
    cors.responder(api_key.colour)
}

#[options("/color/cycle")]
fn option_cycle_colour(cors: Guard<'_>) -> Responder<&str> {
    cors.responder("Manual OPTIONS preflight handling")
}

fn main() {
    let arg_matches = clap::App::new("EBS")
        .version("0.1.0")
        .author("David Athay <ko2fan@gmail.com>")
        .about("Twitch extention example")
        .args_from_usage("-c, --client_id [client_id] 'Set the id of the client'
        -s, --secret [secret] 'Set the secret'
        -o, --owner_id [owner_id] 'Set the id of the owner'")
        .get_matches();

    let client_id = arg_matches.value_of("client_id");
    let owner_id = arg_matches.value_of("owner_id");
    let secret = arg_matches.value_of("secret");

    if client_id.is_none() || owner_id.is_none() || secret.is_none() {
        println!("One or more parameters not specified");
        println!("{:?} {:?} {:?}", client_id, owner_id, secret);
        std::process::exit(1);
    }

    let allowed_origins = AllowedOrigins::All;

    let cors = rocket_cors::CorsOptions {
        allowed_origins,
        allowed_methods: vec![Method::Get, Method::Options, Method::Post].into_iter().map(From::from).collect(),
        allowed_headers: AllowedHeaders::some(&["Authorization", "Accept"]),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors().expect("Unable to set cors options");

    rocket::ignite().mount("/", routes![
        index,
        query_colour,
        option_query_colour,
        cycle_colour,
        option_cycle_colour])
    .mount("/", rocket_cors::catch_all_options_routes())
    .manage(Secrets {
        client_id: client_id.unwrap().into(),
        owner_id: owner_id.unwrap().into(),
        secret: secret.unwrap().into()})
    .manage(cors).launch();
}
