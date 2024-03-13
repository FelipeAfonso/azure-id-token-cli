use clap::Parser;
use clipboard::ClipboardProvider;
use colored::Colorize;
use core::{panic, time};
use json::JsonValue::{self};
use log::info;
use std::{cell::RefCell, io::Write, thread::sleep};
use url::Url;

/// Get an AD id_token from your terminal!
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Your azure ad tenant id
    #[arg(short, long)]
    tenant_id: String,

    /// Your azure ad client id
    #[arg(short, long)]
    client_id: String,

    /// Your azure ad client secret
    #[arg(short, long)]
    client_secret: String,
}

#[derive(Clone)]
struct Tokens {
    id_token: String,
    access_token: String,
    refresh_token: String,
}

static NUMBER_OF_RETRIES: i8 = 50;
fn get_az_url(tenant_id: String, path: String) -> String {
    format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/{}",
        tenant_id, path
    )
}

fn write_tokens(tokens: Tokens) -> std::io::Result<()> {
    let mut file = std::fs::File::create("./.tokens")?;
    file.write(format!("access_token={}\n", tokens.access_token).as_bytes())
        .expect("couldn't write to file");
    file.write(format!("id_token={}\n", tokens.id_token).as_bytes())
        .expect("couldn't write to file");
    file.write(format!("refresh_token={}", tokens.refresh_token).as_bytes())
        .expect("couldn't write to file");
    std::io::Result::Ok(())
}

fn get_refresh_token() -> Option<String> {
    let content = std::fs::read_to_string("./.tokens").unwrap_or_default();
    let mut lines = content.split("\n");
    let found = lines.find(|line| line.starts_with("refresh_token"));
    match found {
        Some(str) => Some(str.split_at(14).1.to_string()),
        None => None,
    }
}

async fn get_authorization(
    client: reqwest::Client,
    tenant_id: String,
    client_id: String,
    client_secret: String,
) -> JsonValue {
    let dcode_url = get_az_url(tenant_id, String::from("devicecode"));
    let url = match Url::parse(&dcode_url) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("Error parsing url");
            panic!()
        }
    };
    let body = [
        "scope=openid offline_access",
        format!("client_id={}", client_id).as_str(),
        format!("client_secret={}", client_secret).as_str(),
    ]
    .join("&");

    let request = match client.post(url).body(body).send().await {
        Ok(r) => r,
        Err(_) => {
            eprintln!("failed to request authorization code");
            panic!()
        }
    }
    .text()
    .await;
    let response = match json::parse(match &request {
        Ok(r) => r,
        Err(_) => {
            eprintln!("failed to retrieve data from request");
            panic!()
        }
    }) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("failed to retrieve data from request");
            panic!()
        }
    };
    info!("Authorize Response: {:?}", response);
    assert!(response.has_key("message"));
    assert!(response.has_key("device_code"));
    return response;
}

async fn refresh_token(
    client: reqwest::Client,
    refresh_token: String,
    tenant_id: String,
    client_id: String,
) -> Result<JsonValue, String> {
    let refresh_url = get_az_url(tenant_id, String::from("token"));
    let refresh_body = [
        "grant_type=refresh_token",
        format!("client_id={}", client_id).as_str(),
        format!("refresh_token={}", refresh_token).as_str(),
    ]
    .join("&");
    let refresh_res = match client
        .post(refresh_url.clone())
        .body(refresh_body.clone())
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            eprintln!("failed to refresh, logging in");
            panic!()
        }
    }
    .text()
    .await;

    info!("Response: {:?}", refresh_res);
    let parsed = json::parse(match &refresh_res {
        Ok(r) => r,
        Err(_) => {
            eprintln!("failed to retrieve data from request");
            panic!()
        }
    })
    .unwrap();
    info!(
        "{}{:?}",
        "Parsed Refresh: ".blue(),
        parsed.to_string().blue()
    );
    if parsed.has_key("id_token") {
        Ok(parsed)
    } else {
        Err(String::from("Failed to retrieve data"))
    }
}

async fn get_token(
    client: reqwest::Client,
    device_code: String,
    tenant_id: String,
    client_id: String,
    client_secret: String,
) -> JsonValue {
    let poll_url = get_az_url(tenant_id, String::from("token"));
    let poll_body = [
        "grant_type=urn:ietf:params:oauth:grant-type:device_code",
        format!("client_id={}", client_id).as_str(),
        format!("client_secret={}", client_secret).as_str(),
        format!("device_code={}", device_code).as_str(),
    ]
    .join("&");
    let poll_res = match client
        .post(poll_url.clone())
        .body(poll_body.clone())
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            eprintln!("failed attempt, retrying...");
            panic!()
        }
    }
    .text()
    .await;
    info!("Response: {:?}", poll_res);
    return json::parse(match &poll_res {
        Ok(r) => r,
        Err(_) => {
            eprintln!("failed to retrieve data from request");
            panic!()
        }
    })
    .unwrap();
}

fn set_clipboard(content: String) {
    let mut clipboard_context = match clipboard::ClipboardContext::new() {
        Ok(clip) => clip,
        Err(_) => {
            eprintln!("failed to initialize clipboard api");
            panic!()
        }
    };
    let _ = clipboard_context.set_contents(content);
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();
    let client = reqwest::Client::new();
    let r_token = get_refresh_token().unwrap_or_default();
    info!("{}", "r_token detected".green());
    let refresh_response = refresh_token(
        client.clone(),
        r_token,
        args.tenant_id.clone(),
        args.client_id.clone(),
    )
    .await;
    let tokens: Tokens = match refresh_response {
        Ok(refresh_response) => {
            let id_token = refresh_response["id_token"]
                .as_str()
                .expect("failed to get id_token");
            let access_token = refresh_response["access_token"]
                .as_str()
                .expect("failed to get access_token");
            let refresh_token = refresh_response["refresh_token"]
                .as_str()
                .expect("failed to get refresh_token");
            println!(
                "{}",
                "Successfully refresh token and retrieved id_token".green()
            );
            Tokens {
                id_token: id_token.to_string(),
                access_token: access_token.to_string(),
                refresh_token: refresh_token.to_string(),
            }
        }
        Err(_) => {
            let authorize_response = get_authorization(
                client.clone(),
                args.tenant_id.clone(),
                args.client_id.clone(),
                args.client_secret.clone(),
            )
            .await;
            let device_code: &str = match &authorize_response["device_code"].as_str() {
                Some(r) => r,
                None => {
                    eprintln!("device code is not serializable");
                    panic!()
                }
            };

            // prints the message retrieved from MS
            println!("{}", "Thanks for using the authenticator".green().bold());
            println!(
                "To sign in, use a web browser to open the page {} and enter
 the code {} to authenticate.",
                "https://microsoft.com/devicelogin".blue().underline(),
                &authorize_response["user_code"].to_string().magenta().bold(),
            );
            info!("{}", &authorize_response["device_code"]);
            set_clipboard(
                authorize_response["user_code"]
                    .as_str()
                    .expect("failed to parse user_code")
                    .to_string(),
            );

            let retry_n = RefCell::new(0);
            let polling_response = RefCell::new(JsonValue::Null);
            let is_not_expired = || retry_n.borrow().lt(&NUMBER_OF_RETRIES);
            let is_polling = || {
                !polling_response.borrow().is_object()
                    || polling_response.borrow()["error"].eq("authorization_pending")
            };

            while is_not_expired() && is_polling() {
                sleep(time::Duration::from_secs(2));
                info!("Retry attempt: {}", retry_n.borrow());
                *retry_n.borrow_mut() += 1;
                *polling_response.borrow_mut() = get_token(
                    client.clone(),
                    device_code.to_string(),
                    args.tenant_id.clone(),
                    args.client_id.clone(),
                    args.client_secret.clone(),
                )
                .await;
            }
            let polling_response: JsonValue = polling_response.into_inner();
            if polling_response.has_key("id_token") {
                let id_token = polling_response["id_token"]
                    .as_str()
                    .expect("failed to get id_token");
                let access_token = polling_response["access_token"]
                    .as_str()
                    .expect("failed to get access_token");
                let refresh_token = polling_response["refresh_token"]
                    .as_str()
                    .expect("failed to get refresh_token");
                println!("{}", "Successfully retrieved id token".green());
                Tokens {
                    id_token: id_token.to_string(),
                    access_token: access_token.to_string(),
                    refresh_token: refresh_token.to_string(),
                }
            } else {
                eprintln!("could not request id_token");
                panic!()
            }
        }
    };
    let id_token = tokens.id_token.clone();
    let _ = std::io::stdout().write_all(id_token.as_bytes());
    set_clipboard(id_token);
    let _ = write_tokens(tokens.clone());
}
