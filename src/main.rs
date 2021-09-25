#![feature(proc_macro_hygiene, decl_macro)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::error::Error;

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

fn get_new_colour(token: &str, secret: &Secrets) -> Result<ApiKey, Box<dyn Error>> {
    let bearer = token.split(" ").last().unwrap();
    let base64_secret = base64::decode(&secret.secret)?;

    let (_header, payload) = decode(&bearer,
        &base64_secret,
        Algorithm::HS256,
        &ValidationOptions::default())?;

    let to_strip = String::from('"');
    let channel_id = payload["channel_id"].to_string().chars().filter(|&c| !to_strip.contains(c)).collect();

    let api = ApiKey { secret: secret.clone(), channel_id, colour: RandomColor::new().to_hex() };
    
    Ok(api)
}

impl<'a, 'r> FromRequest<'a, 'r> for ApiKey {
    type Error = ApiKeyError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let keys= request.headers().get("Authorization").collect::<Vec<_>>();
        let secret = request.guard::<State<Secrets>>().unwrap();
        
        match keys.len() {
            0 => Outcome::Failure((Status::BadRequest, ApiKeyError::Missing)),
            1 => {
                let color = get_new_colour(keys[0], &secret);
                match color {
                    Ok(api_key) => Outcome::Success(api_key),
                    Err(_) => Outcome::Failure((Status::BadRequest, ApiKeyError::Invalid)),
                }
            }
            _ => Outcome::Failure((Status::BadRequest, ApiKeyError::BadCount)),
        }
    }
}

fn create_jwt(secret: &String, owner_id: &String, channel_id: &String) -> Result<String, Box<dyn Error>> {
    let secret_base64 = base64::decode(secret)?;

    let expiry = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 600;
    let header = json!({});
    let payload = json!({
        "exp": expiry,
        "channel_id": channel_id,
        "user_id": owner_id,
        "role": "external",
        "pubsub_perms": {
            "send": ['*']
        }
    });
    
    let jwt = encode(header, &secret_base64, &payload, Algorithm::HS256)?;

    Ok(format!("Bearer {}", jwt))
}

fn broadcast_colour_change(channel_id: String, colour: String, secret: &Secrets) -> Result<(), ureq::Error> {
    match create_jwt(&secret.secret, &secret.owner_id, &channel_id) {
        Ok(jwt) => {
            let response = ureq::post(
                format!("https://api.twitch.tv/extensions/message/{}", channel_id).as_str())
                .set("Authorization", &jwt)
                .set("Client-Id", &secret.client_id)
                .set("Content-Type", "application/json")
                .send_json(json!({ "content_type": "application/json", "message": colour, "targets": ["broadcast"]}));

                if response.error() {
                    return Err(ureq::Error::ConnectionFailed("Error connecting".into()));
                }
        }
        Err(e) => eprintln!("Could not create jwt: {:?}", e)
    }

    Ok(())
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
    let result = broadcast_colour_change(api_key.channel_id,api_key.colour.clone(), &api_key.secret);
    match result {
        Ok(()) => (),
        Err(err) => eprintln!("Error broadcasting colour change: {:?}", err)
    }

    cors.responder(api_key.colour)
}

#[options("/color/cycle")]
fn option_cycle_colour(cors: Guard<'_>) -> Responder<&str> {
    cors.responder("Manual OPTIONS preflight handling")
}

fn run(client_id: String, owner_id: String, secret: String) {
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
    .manage(Secrets { client_id, owner_id, secret })
    .manage(cors).launch();
}

fn main() {
    let arg_matches = clap::App::new("EBS")
        .version("0.1.1")
        .author("David Athay <ko2fan@gmail.com>")
        .about("Twitch extention example")
        .args_from_usage("-c, --client_id <client_id> 'Set the id of the client'
        -s, --secret <secret> 'Set the secret'
        -o, --owner_id <owner_id> 'Set the id of the owner'")
        .get_matches();

    let client_id = arg_matches.value_of("client_id").unwrap();
    let owner_id = arg_matches.value_of("owner_id").unwrap();
    let secret = arg_matches.value_of("secret").unwrap();

    run(client_id.into(), owner_id.into(), secret.into());
}
