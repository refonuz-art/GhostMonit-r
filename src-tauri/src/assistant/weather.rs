//! Weather from Open-Meteo (no key). Only the city name and its coordinates leave the PC,
//! and only when the user asks about the weather.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Day {
    pub min: f64,
    pub max: f64,
    pub rain_chance: Option<f64>,
    pub sky: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Weather {
    pub place: String,
    pub temp: f64,
    pub feels: f64,
    pub humidity: Option<f64>,
    pub wind: Option<f64>,
    pub sky: String,
    pub today: Option<Day>,
    pub tomorrow: Option<Day>,
}

/// WMO weather interpretation codes in Turkish.
pub fn sky(code: i64) -> &'static str {
    match code {
        0 => "açık",
        1 => "çoğunlukla açık",
        2 => "parçalı bulutlu",
        3 => "kapalı",
        45 | 48 => "sisli",
        51 | 53 | 55 => "çiseleyen yağmurlu",
        56 | 57 => "dondurucu çiseli",
        61 => "hafif yağmurlu",
        63 => "yağmurlu",
        65 => "şiddetli yağmurlu",
        66 | 67 => "dondurucu yağmurlu",
        71 => "hafif karlı",
        73 => "karlı",
        75 => "yoğun karlı",
        77 => "kar taneli",
        80 | 81 => "sağanak yağışlı",
        82 => "şiddetli sağanaklı",
        85 | 86 => "kar sağanaklı",
        95 => "gök gürültülü fırtınalı",
        96 | 99 => "dolu ile gök gürültülü fırtınalı",
        _ => "değişken",
    }
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => o.push(*b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn get(url: &str) -> Result<Value, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(12))).build().into();
    let mut r = agent.get(url).header("User-Agent", "GhostMonitor").call().map_err(|_| "Hava durumu servisine bağlanılamadı".to_string())?;
    if !r.status().is_success() {
        return Err(format!("Hava durumu servisi yanıt vermedi (HTTP {})", r.status().as_u16()));
    }
    let body = r.body_mut().read_to_string().map_err(|e| e.to_string())?;
    serde_json::from_str(&body).map_err(|e| e.to_string())
}

fn day(d: &Value, i: usize) -> Option<Day> {
    Some(Day {
        min: d["temperature_2m_min"][i].as_f64()?,
        max: d["temperature_2m_max"][i].as_f64()?,
        rain_chance: d["precipitation_probability_max"][i].as_f64(),
        sky: sky(d["weather_code"][i].as_i64().unwrap_or(-1)).into(),
    })
}

pub fn fetch(city: &str) -> Result<Weather, String> {
    let city = city.trim();
    if city.is_empty() || city.chars().count() > 60 {
        return Err("Şehir adı geçersiz".into());
    }
    let g = get(&format!("https://geocoding-api.open-meteo.com/v1/search?name={}&count=1&language=tr&format=json", enc(city)))?;
    let r = g["results"].get(0).ok_or_else(|| format!("“{city}” adında bir yer bulamadım"))?;
    let (lat, lon) = (r["latitude"].as_f64().ok_or("konum yok")?, r["longitude"].as_f64().ok_or("konum yok")?);
    let place = r["name"].as_str().unwrap_or(city).to_string();
    let f = get(&format!(
        "https://api.open-meteo.com/v1/forecast?latitude={lat:.3}&longitude={lon:.3}\
         &current=temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m\
         &daily=temperature_2m_max,temperature_2m_min,precipitation_probability_max,weather_code\
         &timezone=auto&forecast_days=2"
    ))?;
    let c = &f["current"];
    Ok(Weather {
        place,
        temp: c["temperature_2m"].as_f64().ok_or("Hava durumu verisi eksik")?,
        feels: c["apparent_temperature"].as_f64().unwrap_or(f64::NAN),
        humidity: c["relative_humidity_2m"].as_f64(),
        wind: c["wind_speed_10m"].as_f64(),
        sky: sky(c["weather_code"].as_i64().unwrap_or(-1)).into(),
        today: day(&f["daily"], 0),
        tomorrow: day(&f["daily"], 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_turkish_city_names() {
        assert_eq!(enc("İzmir"), "%C4%B0zmir");
        assert_eq!(enc("a&b=c"), "a%26b%3Dc");
        assert_eq!(sky(3), "kapalı");
    }

    #[test]
    #[ignore = "network"]
    fn live_weather() {
        let w = fetch("Ankara").unwrap();
        assert_eq!(w.place, "Ankara");
    }
}
