//! `entropa-contact`: the contact-form service. Needs `GMAIL_SA_KEY`, `GMAIL_SENDER` and `CONTACT_TO`.
use entropa_contact::{app, GmailMailer, Limits};
use std::net::SocketAddr;
use std::sync::Arc;

fn main() {
    let Some(mailer) = GmailMailer::from_env() else {
        eprintln!("error: GMAIL_SA_KEY, GMAIL_SENDER and CONTACT_TO must be set");
        std::process::exit(1);
    };
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    else {
        std::process::exit(1);
    };
    let limits = Limits {
        per_ip_per_hour: 5,
        daily_cap: 50,
    };
    let result = rt.block_on(async move {
        let l = tokio::net::TcpListener::bind((bind.as_str(), port)).await?;
        axum::serve(
            l,
            app(Arc::new(mailer), limits).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    if result.is_err() {
        std::process::exit(1);
    }
}
