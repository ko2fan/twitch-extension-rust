#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
use rocket::State;
use rocket::request::{Request, Outcome, FromRequest};
use rocket::http::{Method, Status};
use rocket_cors::{AllowedHeaders, AllowedOrigins, Guard, Responder};

use jwt_simple::prelude::*;


extern crate base64;

struct Secrets {
    client_id: String,
    owner_id: String,
    secret: String
}

struct ApiKey(String);

#[derive(Debug)]
enum ApiKeyError {
    BadCount,
    Missing,
    Invalid,
}

fn is_valid(token: &str, secret: &String) -> bool {
    println!("token: {}  secret: {}", token, secret);
    let bearer = token.split(" ").last().unwrap();
    println!("bearer: {}", bearer);
    let base64_secret = base64::decode(secret).unwrap();
    println!("{:?}", base64_secret);
    // let result = decode(&bearer, &base64_secret, Algorithm::HS256, &ValidationOptions::default());
    // if result.is_err() { eprintln!("{:?}", result.err()); return false; }
    // let (header, payload) = result.unwrap();
    let key = HS256Key::from_bytes(base64_secret.as_ref());

    let claims = key.verify_token::<NoCustomClaims>(&bearer, None);

    if claims.is_err() {
        println!("{:?}", claims);
        return false;
    }
    else {
        println!("It works!");
    }

    true
}

impl<'a, 'r> FromRequest<'a, 'r> for ApiKey {
    type Error = ApiKeyError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        let secrets = request.guard::<State<Secrets>>().unwrap();
        
        match keys.len() {
            0 => Outcome::Failure((Status::BadRequest, ApiKeyError::Missing)),
            1 if is_valid(keys[0], &secrets.secret) => Outcome::Success(ApiKey(String::from("Test"))),
            1 => Outcome::Failure((Status::BadRequest, ApiKeyError::Invalid)),
            _ => Outcome::Failure((Status::BadRequest, ApiKeyError::BadCount)),
        }
    }
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/color/query")]
fn query_colour(cors: Guard<'_>, _api_key: ApiKey) -> Responder<&str> {
    cors.responder("#6164fe")
}

#[options("/color/query")]
fn option_query_colour(cors: Guard<'_>) -> Responder<&str> {
    cors.responder("Manual OPTIONS preflight handling")
}

#[post("/color/cycle")]
fn cycle_colour(cors: Guard<'_>, _api_key: ApiKey) -> Responder<&str> {
    cors.responder("#ffffff")
}

#[options("/color/cycle")]
fn option_cycle_colour(cors: Guard<'_>) -> Responder<&str> {
    cors.responder("Manual OPTIONS preflight handling")
}

fn main() {
    let arg_matches = clap::App::new("backend")
        .version("0.0.1")
        .author("David Athay <ko2fan@gmail.com>")
        .about("Twitch extention service")
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
