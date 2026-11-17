//! What is playing right now, read from Windows' media session (the same source as the
//! volume flyout), and play/pause/skip on it.

use serde::Serialize;
use windows::Media::Control::{
    GlobalSystemMediaTransportControlsSession as Session,
    GlobalSystemMediaTransportControlsSessionManager as Manager,
    GlobalSystemMediaTransportControlsSessionPlaybackStatus as Status,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NowPlaying {
    pub title: String,
    pub artist: String,
    /// App that owns the session, e.g. "Spotify.exe" or a Store app id.
    pub app: String,
    pub playing: bool,
    /// Seconds; None when the app does not report a timeline.
    pub position: Option<f64>,
    pub duration: Option<f64>,
}

fn session() -> windows::core::Result<Option<Session>> {
    let mgr = Manager::RequestAsync()?.join()?;
    Ok(mgr.GetCurrentSession().ok())
}

const TICKS: f64 = 10_000_000.0;

pub fn now() -> Result<Option<NowPlaying>, String> {
    let Some(s) = session().map_err(|e| e.to_string())? else { return Ok(None) };
    let props = s.TryGetMediaPropertiesAsync().and_then(|op| op.join()).map_err(|e| e.to_string())?;
    let title = props.Title().map(|h| h.to_string()).unwrap_or_default();
    if title.trim().is_empty() {
        return Ok(None);
    }
    let playing = s
        .GetPlaybackInfo()
        .and_then(|i| i.PlaybackStatus())
        .map(|st| st == Status::Playing)
        .unwrap_or(false);
    let (position, duration) = match s.GetTimelineProperties() {
        Ok(tl) => {
            let end = tl.EndTime().map(|t| t.Duration as f64 / TICKS).unwrap_or(0.0);
            let pos = tl.Position().map(|t| t.Duration as f64 / TICKS).unwrap_or(0.0);
            if end > 0.0 { (Some(pos.clamp(0.0, end)), Some(end)) } else { (None, None) }
        }
        Err(_) => (None, None),
    };
    Ok(Some(NowPlaying {
        title,
        artist: props.Artist().map(|h| h.to_string()).unwrap_or_default(),
        app: s.SourceAppUserModelId().map(|h| h.to_string()).unwrap_or_default(),
        playing,
        position,
        duration,
    }))
}

pub fn control(action: &str) -> Result<(), String> {
    let Some(s) = session().map_err(|e| e.to_string())? else { return Err("Şu anda çalan bir şey yok".into()) };
    let op = match action {
        "toggle" => s.TryTogglePlayPauseAsync(),
        "next" => s.TrySkipNextAsync(),
        "prev" => s.TrySkipPreviousAsync(),
        _ => return Err("Bilinmeyen medya komutu".into()),
    };
    let ok = op.and_then(|o| o.join()).map_err(|e| e.to_string())?;
    if ok { Ok(()) } else { Err("Uygulama bu komutu kabul etmedi".into()) }
}
