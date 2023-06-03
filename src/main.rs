use std::env;

use anyhow::Result;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::{extract::Form, response::Html, routing::get, Router, ServiceExt};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use reqwest::{multipart, Client};
use serde::Deserialize;
use serde_json::Value;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone)]
struct AppState {
    captcha_secret_key: String,
    email_username: String,
    email_password: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let app = Router::new()
        .with_state(AppState {
            captcha_secret_key: env::var("CAPTCHA_SECRET_KEY")?,
            email_username: env::var("EMAIL_USERNAME")?,
            email_password: env::var("EMAIL_PASSWORD")?,
        })
        .route("/", get(show_form).post(accept_form));
    axum::Server::bind(&"0.0.0.0:3000".parse()?)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn show_form() -> Html<&'static str> {
    Html(
        r#"
        <!doctype html>
        <head>
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        </head>
        <html>
            <body>
                <form action="/" method="post">
                    <label for="name">
                        Enter your name:
                        <input type="text" name="name">
                    </label>

                    <label>
                        Enter your email:
                        <input type="text" name="email">
                    </label>
                    
                    <div class="cf-turnstile" data-sitekey="0x4AAAAAAAFjofmqsL3WMhzb"></div>
                    
                    <input type="submit" value="Subscribe!">
                </form>
            </body>
        </html>
        "#,
    )
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Input {
    name: String,
    email: String,
    #[serde(rename = "cf-turnstile-response")]
    cf_turnstile_response: String,
}

async fn accept_form(
    headers: HeaderMap,
    State(state): State<AppState>,
    Form(form_payload): Form<Input>,
) {
    let token = form_payload.cf_turnstile_response;
    let ip = headers
        .get("CF-Connecting-IP")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    dbg!(&SECRET_KEY, &token, &ip);
    let form = multipart::Form::new()
        .text("secret", state.captcha_secret_key)
        .text("response", token)
        .text("remoteip", ip);

    let client = Client::new();
    let resp: Value = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .multipart(form)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();

    let success = resp["success"].as_bool().unwrap();

    if success {
        let email = Message::builder()
            .from(
                "Patrick Lamprecht <lamprecht.patrick1@gmail.com>"
                    .parse()
                    .unwrap(),
            )
            .reply_to(
                "Patrick Lamprecht <lamprecht.patrick1@gmail.com>"
                    .parse()
                    .unwrap(),
            )
            .to(format!("{} <{}>", form_payload.name, form_payload.email)
                .parse()
                .unwrap())
            .subject("Happy new year")
            .header(ContentType::TEXT_PLAIN)
            .body(String::from("Be happy!"))
            .unwrap();

        let creds = Credentials::new(state.email_username, state.email_password);

        // Open a remote connection to gmail
        let mailer = SmtpTransport::relay("smtp.gmail.com")
            .unwrap()
            .credentials(creds)
            .build();

        // Send the email
        match mailer.send(&email) {
            Ok(_) => println!("Email sent successfully!"),
            Err(e) => panic!("Could not send email: {e:?}"),
        }
    }
}
