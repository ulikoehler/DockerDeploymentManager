use crate::config::{NotifierConfig, SmtpTls};
use crate::protocol::AlertEvent;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use tracing::{error, info};

/// A notification to deliver.
#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    pub title: String,
    pub body: String,
    pub service: String,
    pub severity: String, // "info" | "firing" | "resolved"
}

impl Notification {
    pub fn from_event(ev: &AlertEvent) -> Self {
        Self {
            title: format!("[ddm] {} — {}", ev.service, ev.rule),
            body: format!(
                "{}\n\n{}",
                ev.message,
                ev.detail.clone().unwrap_or_default()
            ),
            service: ev.service.clone(),
            severity: ev.state.clone(),
        }
    }
}

fn env_or<'a>(value: &'a Option<String>, env: &'a Option<String>) -> Option<String> {
    if let Some(v) = value {
        return Some(v.clone());
    }
    env.as_ref().and_then(|e| std::env::var(e).ok())
}

/// Send a notification through the configured notifier. Retries once.
pub async fn send(cfg: &NotifierConfig, n: &Notification) -> Result<()> {
    let res = send_once(cfg, n).await;
    match res {
        Ok(()) => {
            info!("notification sent via {}", cfg.id());
            Ok(())
        }
        Err(e) => {
            error!("notify {} failed ({e:#}), retrying once", cfg.id());
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            send_once(cfg, n).await
        }
    }
}

async fn send_once(cfg: &NotifierConfig, n: &Notification) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    match cfg {
        NotifierConfig::SlackWebhook { url, url_env, .. } => {
            let url =
                env_or(url, url_env).context("slack notifier has no url/url_env configured")?;
            let text = format!("*{}*\n```{body}```", n.title, body = n.body);
            client
                .post(&url)
                .json(&serde_json::json!({ "text": text }))
                .send()
                .await?
                .error_for_status()?;
        }
        NotifierConfig::Telegram {
            bot_token_env,
            chat_id,
            ..
        } => {
            let token = bot_token_env
                .as_ref()
                .and_then(|e| std::env::var(e).ok())
                .context("telegram bot_token_env not set")?;
            let url = format!("https://api.telegram.org/bot{token}/sendMessage");
            client
                .post(&url)
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "text": format!("{}\n\n{}", n.title, n.body),
                }))
                .send()
                .await?
                .error_for_status()?;
        }
        NotifierConfig::Email {
            smtp_host,
            smtp_port,
            smtp_tls,
            username_env,
            password_env,
            from,
            to,
            ..
        } => {
            send_email(
                smtp_host,
                *smtp_port,
                *smtp_tls,
                username_env,
                password_env,
                from,
                to,
                n,
            )
            .await?;
        }
        NotifierConfig::Webhook { url, headers, .. } => {
            let mut req = client.post(url).json(&serde_json::json!({
                "title": n.title,
                "body": n.body,
                "service": n.service,
                "severity": n.severity,
            }));
            for (k, v) in headers {
                req = req.header(k, v);
            }
            req.send().await?.error_for_status()?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_email(
    host: &str,
    port: u16,
    tls: SmtpTls,
    username_env: &Option<String>,
    password_env: &Option<String>,
    from: &str,
    to: &[String],
    n: &Notification,
) -> Result<()> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let mut builder = Message::builder()
        .from(from.parse().context("invalid from address")?)
        .subject(&n.title)
        .header(ContentType::TEXT_PLAIN);
    for t in to {
        builder = builder.to(t.parse().context("invalid to address")?);
    }
    let msg = builder.body(n.body.clone())?;

    let mut transport_builder = match tls {
        SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host)?,
        SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?,
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
    }
    .port(port);

    if let (Some(u), Some(p)) = (
        username_env.as_ref().and_then(|e| std::env::var(e).ok()),
        password_env.as_ref().and_then(|e| std::env::var(e).ok()),
    ) {
        transport_builder = transport_builder.credentials(Credentials::new(u, p));
    }
    transport_builder.build().send(msg).await?;
    Ok(())
}

/// List notifiers for the API (secrets redacted).
pub fn describe(notifiers: &[NotifierConfig]) -> Vec<serde_json::Value> {
    notifiers
        .iter()
        .map(|n| {
            let mut v = serde_json::to_value(n).unwrap_or_default();
            // strip secret-bearing fields
            for key in [
                "url",
                "url_env",
                "bot_token_env",
                "password_env",
                "username_env",
            ] {
                if let Some(map) = v.as_object_mut() {
                    if let Some(val) = map.get_mut(key) {
                        *val = serde_json::Value::String("***".into());
                    }
                }
            }
            v
        })
        .collect()
}

/// Index notifiers by id.
#[allow(dead_code)]
pub fn index(notifiers: &[NotifierConfig]) -> HashMap<String, NotifierConfig> {
    notifiers
        .iter()
        .map(|n| (n.id().to_string(), n.clone()))
        .collect()
}
