# AI Destekli Web Zafiyet Tarayıcısı

OWASP Top 10 (2021) kategorilerini hedefleyen, yerel LLM (Ollama) ile zenginleştirilmiş Türkçe çıktılı web zafiyet tarayıcısı. Hem **komut satırı (CLI)** hem de **web arayüzü** üzerinden kullanılabilir, hazır savunmasız test ortamlarıyla (DVWA, Juice Shop, WebGoat) birlikte Docker üzerinde tek komutla ayağa kalkar.

> **Eğitim amaçlıdır.** Yalnızca size ait sistemler veya açıkça izinli savunmasız laboratuvar ortamlarına karşı kullanın.

---

## İçindekiler

- [Özellikler](#özellikler)
- [Mimari](#mimari)
- [Hızlı Başlangıç (Docker)](#hızlı-başlangıç-docker)
- [Kullanım: Web Arayüzü](#kullanım-web-arayüzü)
- [Kullanım: CLI](#kullanım-cli)
- [OWASP Modülleri](#owasp-modülleri)
- [LLM (Ollama) Entegrasyonu](#llm-ollama-entegrasyonu)
- [Proje Yapısı](#proje-yapısı)
- [Geliştirme](#geliştirme)
- [Sınırlamalar](#sınırlamalar)

---

## Özellikler

- **10 OWASP modülü** — A01'den A10'a kadar tüm 2021 kategorileri
- **Web arayüzü** — Canlı log akışı (WebSocket), severity renkli bulgu kartları, filtrelenebilir rapor
- **CLI** — Mevcut `python main.py` kullanımı tamamen korunur
- **Hazır test ortamları** — DVWA + Juice Shop + WebGoat tek `docker compose` ile ayağa kalkar
- **DVWA otomatik setup** — Veritabanı kurulumu + login + cookie alma tek tıkla
- **AI analizi** — Tespit edilen her bulgu için Türkçe risk açıklaması, düzeltme kodu, önlem listesi
- **Çoklu çıktı formatı** — JSON, TXT, yazdırma/PDF, panoya kopyala
- **Tarama geçmişi** — Son 20 taramaya ana sayfadan erişim
- **Eş zamanlı tarama** — Aynı anda 3 farklı hedef taranabilir

---

## Mimari

```
┌──────────────────────────────────────────────────────────────────┐
│                         Kullanıcı (Tarayıcı)                     │
└────────────────────────────────┬─────────────────────────────────┘
                                 │ HTTP + WebSocket
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  nginx:alpine  (port 8090 → 80)                                  │
│  • Statik dosya servisi    • WS upgrade (/ws/)                   │
│  • API proxy (/api/)       • Sayfalar (/, /report/)              │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  scanner  (FastAPI / uvicorn :8000)                              │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  web/app.py        — HTTP + WebSocket endpoints            │  │
│  │  web/scan_manager  — Subprocess yönetimi, log parse        │  │
│  │  web/static/       — index.html, report.html, app.js, css  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │ subprocess                        │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  guvenlik_proje/main.py  (mevcut CLI tarayıcı)             │  │
│  │  ├─ core/    http_client, llm_client, base_module          │  │
│  │  └─ modules/ A01..A10                                      │  │
│  └────────────────────────────────────────────────────────────┘  │
└────────┬─────────────────────────────────────┬───────────────────┘
         │                                     │
         ▼ HTTP                                ▼ HTTP (/api/generate)
┌────────────────────────┐         ┌──────────────────────────────┐
│  Test Ortamları        │         │  ollama (LLM servisi)        │
│  ┌──────────────────┐  │         │  • llama3 / llama3.2:3b      │
│  │ dvwa             │  │         │  • Türkçe analiz üretir      │
│  │ juice-shop:3000  │  │         └──────────────────────────────┘
│  │ webgoat:8080     │  │
│  └──────────────────┘  │
└────────────────────────┘
```

### Tarama akışı

1. Kullanıcı web arayüzünde URL + cookie + modüller girer, "Taramayı Başlat"a basar
2. `POST /api/scan/start` → `scan_manager` yeni `ScanJob` oluşturur
3. Subprocess olarak `python main.py -u <url> -o /tmp/scans/<id>.json` çalıştırılır
4. Stdout satır satır okunur, log/module_begin/module_done event'lerine dönüştürülüp **WebSocket** üzerinden tarayıcıya akıtılır
5. Tarama bitince JSON raporu okunur, `scan_complete` event'iyle gönderilir
6. Frontend bulguları kart olarak render eder, "Detaylı Rapor" yeni sekmede açılır

### Önemli tasarım kararları

| Karar | Sebep |
|-------|-------|
| **subprocess** (import değil) | Mevcut `main.py` argparse + `sys.exit()` kullanıyor; import izolasyonu zor. Subprocess çıkış kodunu (0/1/2) doğal kullanır, stdout'tan event akışı sağlar. |
| **Bulgular bellekte** | Ders projesi için DB overkill. `/tmp/scans/` volume'a bağlı, restart'a dayanır. |
| **3 eş zamanlı limit** | Asyncio + subprocess işiyle yerel kaynak korunur. Aşılınca HTTP 429. |
| **LLM opsiyonel** | Ollama erişilemezse `--no-llm` ile tarama yapılabilir; mimari yine çalışır. |
| **Plugin pattern** | Yeni OWASP modülü için sadece `BaseModule`'den türet + `main.py`'deki `_MODULE_REGISTRY`'ye ekle. |

---

## Hızlı Başlangıç (Docker)

### Önkoşullar

- Docker Desktop (Windows/macOS) veya Docker Engine + Compose (Linux)
- ~4 GB boş disk (test ortamı image'ları için)

### Tek komutla başlat

```bash
# Sadece tarayıcı + web arayüzü + Ollama
docker compose up --build

# + DVWA, Juice Shop, WebGoat test ortamlarıyla birlikte
docker compose -f docker-compose.yml -f docker-compose.test.yml up --build
```

Sonra tarayıcıda:

```
http://localhost:8090
```

---

## Kullanım: Web Arayüzü

### 1. Hazır test ortamı kullan

1. Ana sayfada **DVWA** butonuna tıkla
2. Sistem otomatik olarak DVWA veritabanını kurar, login olur, cookie'yi alır
3. URL ve cookie alanları kendiliğinden dolar
4. (Opsiyonel) Hangi modülleri çalıştırmak istediğini seç
5. **AI Analizi** toggle'ını LLM modeli kuruluysa açık bırak, değilse kapat
6. **Taramayı Başlat**

### 2. Kendi siteni tara

1. URL alanına hedef adresini gir: `https://benim-sitem.com`
2. Login gerektiriyorsa cookie alanına oturum çerezini yapıştır
3. Taramayı başlat

### 3. Sonuçları görüntüle ve dışa aktar

Tarama bitince beş aksiyon butonu görünür:

- **📋 Detaylı Rapor (Yeni Sekme)** — Filtrelenebilir tam rapor sayfası
- **⬇ JSON İndir** — Ham JSON formatında rapor
- **📄 TXT İndir** — İnsan okunabilir düz metin
- **🖨 Yazdır** — Yazdırma diyaloğu (PDF kaydedilebilir)
- **📋 Panoya Kopyala** — Metin halinde clipboard'a

Ana sayfadaki **Son Taramalar** bölümünden eski raporlara erişebilirsin.

---

## Kullanım: CLI

Web arayüzünü kullanmak istemiyorsan, mevcut CLI aynen çalışır:

```bash
# Docker üzerinden CLI çalıştırma
docker run --rm --network guvenlik_proje_internal \
    guvenlik_proje-scanner \
    -u http://dvwa/ --modules A03 --no-llm

# Veya yerel Python ile (bağımlılıkları kur)
cd guvenlik_proje
pip install -r requirements.txt
python main.py -u http://hedef --modules A01,A03 -o rapor.json
```

### CLI argümanları

| Argüman | Açıklama | Varsayılan |
|---------|----------|------------|
| `-u, --url` | Hedef URL (zorunlu) | — |
| `-o, --output` | Çıktı JSON dosyası | `rapor.json` |
| `--modules` | Virgülle ayrılmış modül ID'leri veya `all` | `all` |
| `--no-llm` | LLM analizini devre dışı bırak | açık |
| `--llm-model` | Ollama model adı | `llama3` |
| `--cookie` | Oturum çerezleri | yok |
| `--timeout` | HTTP zaman aşımı (saniye) | `5` |
| `--proxy` | Proxy URL | yok |
| `--verbose` | DEBUG seviyesi log | kapalı |

### Çıkış kodları

- `0` — Tarama temiz, bulgu yok
- `2` — Tarama başarılı, bulgu var
- `1` — Hata

---

## OWASP Modülleri

| ID | Kategori | Tespit Stratejisi | Hangi hedeflerde iyi çalışır |
|----|----------|-------------------|-------------------------------|
| **A01** | Broken Access Control | Force browsing, IDOR, Path Traversal | DVWA, herhangi PHP uygulaması |
| **A02** | Cryptographic Failures | HTTPS/HSTS, güvenli header kontrolü | Herhangi web sitesi |
| **A03** | Injection | SQLi (error + time-based), XSS (reflected) | DVWA (`/vulnerabilities/sqli/`, `/xss_r/`) |
| **A04** | Insecure Design | Rate-limiting, CAPTCHA, account lockout heuristikleri | Login formu olan siteler |
| **A05** | Security Misconfiguration | Header eksikliği, dizin listeleme, dosya açığa çıkması | Herhangi web sitesi |
| **A06** | Vulnerable Components | Server header → CVE eşleşmesi | Apache/Nginx/PHP servis edenler |
| **A07** | Auth Failures | Weak password, brute-force koruması | Login formu olan siteler |
| **A08** | Data Integrity | CSRF token kontrolü, tehlikeli dosya yükleme | Form/upload içeren siteler |
| **A09** | Logging & Monitoring | Request-ID header, brute-force alarm heuristikleri | Sınırlı (kara kutu) |
| **A10** | SSRF | URL parametresi enjeksiyonu, cloud metadata, open redirect | DVWA, URL alan formlar |

### Plugin pattern: yeni modül ekleme

1. `modules/AXX_YeniKategori.py` oluştur, `BaseModule`'den türet
2. `OWASP_ID`, `TITLE` sınıf sabitleri ekle
3. `run() -> List[Finding]` metodu yaz
4. `main.py`'deki `_MODULE_REGISTRY`'ye ekle

Mimarinin başka hiçbir yerine dokunmana gerek yok.

---

## LLM (Ollama) Entegrasyonu

LLM **tespit kararı vermez** — yalnızca statik tespit modüllerinin ürettiği `Finding`'leri Türkçe risk analizi ile zenginleştirir.

### Modeli indirme

```bash
# Container içinden
docker exec -it guvenlik_proje-ollama-1 ollama pull llama3

# veya daha küçük model (önerilir, 2 GB)
docker exec -it guvenlik_proje-ollama-1 ollama pull llama3.2:3b
```

### LLM çıktısı (her bulgu için eklenir)

```json
{
  "risk_seviyesi": "Yüksek",
  "teknik_aciklama": "Bu zafiyet... (max 3 cümle)",
  "kod_duzeltme": "PDO ile parametreli sorgu kullanın...",
  "genel_onlemler": ["WAF kullanın", "Girdi doğrulayın", "..."],
  "llm_guven": "Yüksek",
  "llm_hatasi": false
}
```

LLM erişilemezse `llm_hatasi: true` döner ve tarama yine tamamlanır.

---

## Proje Yapısı

```
guvenlik_proje/
├── guvenlik_proje/              # Çekirdek tarayıcı (CLI)
│   ├── main.py                  # Orkestratör + argparse
│   ├── requirements.txt
│   ├── core/
│   │   ├── base_module.py       # BaseModule ABC, Finding, Severity, Confidence
│   │   ├── http_client.py       # requests.Session + retry + UA rotation
│   │   └── llm_client.py        # Ollama /api/generate istemcisi
│   └── modules/
│       └── A01..A10_*.py        # OWASP modülleri
│
├── web/                         # Web arayüzü
│   ├── app.py                   # FastAPI: endpoint'ler + WebSocket
│   ├── scan_manager.py          # Subprocess yönetimi + log parse + WS broadcast
│   ├── requirements.txt
│   └── static/
│       ├── index.html           # Ana sayfa: form, geçmiş, canlı log
│       ├── report.html          # Filtrelenebilir rapor görüntüleyici
│       ├── app.js               # WebSocket + DOM güncelleme
│       └── style.css            # Dark tema
│
├── docker/
│   ├── Dockerfile               # Python 3.11-slim, scanner + web
│   └── entrypoint.sh            # `web` → uvicorn, diğer → main.py
│
├── nginx/
│   └── nginx.conf               # WS proxy + statik dosyalar
│
├── docker-compose.yml           # scanner + nginx + ollama
└── docker-compose.test.yml      # + dvwa + juice-shop + webgoat
```

---

## Geliştirme

### Volume mount sayesinde anlık kod güncelleme

`web/` klasörü scanner container'ına volume olarak bağlıdır (`docker-compose.yml`'de tanımlı). HTML/CSS/JS değişiklikleri için container restart gerekmez — sadece tarayıcıda **Ctrl+Shift+R** ile hard refresh yap.

Python kodu değişiklikleri için:
```bash
docker restart guvenlik_proje-scanner-1
```

### Logları izleme

```bash
docker logs -f guvenlik_proje-scanner-1
docker logs -f guvenlik_proje-nginx-1
```

### Tüm sistemi temizle

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml down -v
```

`-v` flag'i scan_reports ve ollama_models volume'larını da siler.

---

## Sınırlamalar

- **A04 ve A09** kara kutu testinde sınırlıdır (heuristik kontroller)
- **JavaScript ile çalışan SPA'lar** statik HTML tarayıcısıyla kapsam dışıdır
- **Authentication-gerektiren rotalar** için manuel cookie veya DVWA otomatik setup gerekir
- LLM ilk çağrıda model yüklemesi nedeniyle yavaş olabilir (~10-30s)
- Container restart'ında PHPSESSID gibi oturum çerezleri geçersizleşir (DVWA için otomatik setup butonu bu yüzden var)

---

## Lisans ve Kullanım

Bu proje **Bilgisayar Güvenliği** dersi için akademik amaçla geliştirilmiştir.

**Yalnızca kendi sistemlerinizde veya açıkça izinli laboratuvar ortamlarında kullanın.** İzin alınmamış üçüncü taraf sistemlere tarama yapmak çoğu yargı bölgesinde yasadışıdır.
