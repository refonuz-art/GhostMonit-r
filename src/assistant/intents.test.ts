import { describe, expect, it } from "vitest";
import { parse } from "./intents";

describe("Turkish command parsing", () => {
  it("opens programs and sites", () => {
    expect(parse("Opera'yı aç")).toEqual({ kind: "open", target: "opera", site: null });
    expect(parse("chrome’u başlat lütfen")).toMatchObject({ kind: "open", target: "chrome" });
    expect(parse("not defterini aç")).toMatchObject({ kind: "open", target: "not defterini" });
    expect(parse("YouTube'u aç")).toMatchObject({ kind: "open", target: "youtube", site: "https://www.youtube.com" });
    expect(parse("Ayla, spotify aç", "Ayla")).toMatchObject({ kind: "open", target: "spotify" });
  });

  it("navigates to screens", () => {
    expect(parse("sağlık ekranını aç")).toMatchObject({ kind: "module", id: "health" });
    expect(parse("ayarları aç")).toMatchObject({ kind: "module", id: "settings" });
    expect(parse("tehdit sekmesine geç")).toMatchObject({ kind: "module", id: "threat" });
    expect(parse("ağı göster")).toMatchObject({ kind: "module", id: "network" });
  });

  it("understands weather questions", () => {
    expect(parse("İstanbul'da hava nasıl?")).toEqual({ kind: "weather", city: "istanbul", when: "now" });
    expect(parse("yarın ankarada hava nasıl olacak")).toEqual({ kind: "weather", city: "ankara", when: "tomorrow" });
    expect(parse("hava durumu nasıl")).toEqual({ kind: "weather", city: null, when: "now" });
    expect(parse("dışarıda hava soğuk mu")).toMatchObject({ kind: "weather", city: null });
  });

  it("security actions keep the target", () => {
    expect(parse("chrome'un internetini kes")).toEqual({ kind: "block", target: "chrome" });
    expect(parse("192.168.1.50 adresini engelle")).toEqual({ kind: "block", target: "192.168.1.50" });
    expect(parse("discord'u dondur")).toEqual({ kind: "freeze", target: "discord" });
    expect(parse("steam'i kapat")).toEqual({ kind: "kill", target: "steam" });
    expect(parse("sesini kapat")).toEqual({ kind: "mute" });
    expect(parse("karantinayı göster")).toEqual({ kind: "quarantine" });
  });

  it("answers and confirmations", () => {
    expect(parse("hayır")).toEqual({ kind: "no" });
    expect(parse("evet")).toEqual({ kind: "yes" });
    expect(parse("sus")).toEqual({ kind: "stop" });
    expect(parse("saat kaç")).toEqual({ kind: "time" });
    expect(parse("şüpheli bir durum var mı")).toEqual({ kind: "alerts" });
    expect(parse("sistem nasıl")).toEqual({ kind: "status" });
    expect(parse("ağı tara")).toEqual({ kind: "lanScan" });
    expect(parse("google'da kuantum bilgisayar ara")).toEqual({ kind: "search", engine: "google", query: "kuantum bilgisayar" });
    expect(parse("youtube'da tarkan şımarık aç")).toEqual({ kind: "search", engine: "youtube", query: "tarkan şımarık" });
    expect(parse("evrenin yaşı kaç")).toMatchObject({ kind: "unknown" });
  });
});
