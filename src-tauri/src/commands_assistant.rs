//! IPC for the voice assistant.

use std::sync::Arc;

use serde_json::Value;
use tauri::ipc::{InvokeBody, Request, Response};
use tauri::State;

use crate::assistant::{self, apps, brain, media, speech, weather, whisper};
use crate::state::Shared;

type S<'a> = State<'a, Arc<Shared>>;
type R<T> = Result<T, String>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> R<T> + Send + 'static) -> R<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn assistant_status(s: S) -> assistant::AssistantStatus {
    assistant::status(&s)
}

#[tauri::command]
pub fn assistant_set_azure(s: S, key: Option<String>, region: Option<String>) -> R<assistant::AssistantStatus> {
    assistant::set_azure(&s, key, region)?;
    Ok(assistant::status(&s))
}

#[tauri::command]
pub fn assistant_set_claude(s: S, key: Option<String>) -> R<assistant::AssistantStatus> {
    assistant::set_claude(&s, key)?;
    Ok(assistant::status(&s))
}

/// Neural voice audio (mp3) for `text`.
#[tauri::command]
pub async fn assistant_tts(s: State<'_, Arc<Shared>>, text: String) -> R<Response> {
    let shared = s.inner().clone();
    let (voice, rate) = {
        let st = shared.settings.read();
        (st.assistant_azure_voice.clone(), st.assistant_rate)
    };
    let bytes = blocking(move || speech::synthesize(&shared, &text, &voice, rate)).await?;
    Ok(Response::new(bytes))
}

/// Turkish text from a WAV recording sent as the raw request body.
#[tauri::command]
pub async fn assistant_stt(s: State<'_, Arc<Shared>>, request: Request<'_>) -> R<String> {
    let InvokeBody::Raw(wav) = request.body() else { return Err("Ses kaydı bekleniyordu".into()) };
    let wav = wav.clone();
    let shared = s.inner().clone();
    // Azure when configured, otherwise the offline recogniser.
    blocking(move || {
        if assistant::status(&shared).azure {
            speech::recognize(&shared, &wav)
        } else {
            whisper::transcribe(&shared, &wav)
        }
    })
    .await
}

/// Download and verify the offline recogniser (progress on `gm://assistant-install`).
#[tauri::command]
pub async fn assistant_install_stt(app: tauri::AppHandle, s: State<'_, Arc<Shared>>) -> R<assistant::AssistantStatus> {
    let shared = s.inner().clone();
    blocking(move || {
        whisper::install(&app, &shared)?;
        Ok(assistant::status(&shared))
    })
    .await
}

#[tauri::command]
pub async fn assistant_find_app(query: String) -> R<Vec<apps::AppEntry>> {
    blocking(move || Ok(apps::find(&query, 5))).await
}

#[tauri::command]
pub async fn assistant_launch(target: String) -> R<String> {
    blocking(move || apps::launch(&target)).await
}

#[tauri::command]
pub fn assistant_open_url(url: String) -> R<()> {
    apps::open_url(&url)
}

#[tauri::command]
pub async fn assistant_weather(s: State<'_, Arc<Shared>>, city: Option<String>) -> R<weather::Weather> {
    let city = city.filter(|c| !c.trim().is_empty()).or_else(|| s.settings.read().assistant_city.clone());
    let Some(city) = city else {
        return Err("Hangi şehrin hava durumunu söyleyeyim? Ayarlar → Asistan'dan şehrinizi girebilirsiniz.".into());
    };
    blocking(move || weather::fetch(&city)).await
}

#[tauri::command]
pub async fn assistant_ask(s: State<'_, Arc<Shared>>, system: Value, messages: Value, tools: Value) -> R<Value> {
    let shared = s.inner().clone();
    blocking(move || brain::ask(&shared, system, messages, tools)).await
}

/// What Windows' media session is playing (None when nothing is).
#[tauri::command]
pub async fn media_now() -> R<Option<media::NowPlaying>> {
    blocking(media::now).await
}

/// "toggle" | "next" | "prev" on the current media session.
#[tauri::command]
pub async fn media_control(action: String) -> R<()> {
    blocking(move || media::control(&action)).await
}
