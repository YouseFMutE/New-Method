# Tunnel Project Plan (Server/Client مشترک)

## هدف
ساخت یک ابزار تونل استاندارد و امن برای فوروارد کردن **یک پورت مشخص** از Server به Client.
ابزار باید:
- یک باینری واحد داشته باشد که هم نقش Server و هم Client را اجرا کند.
- CLI و منوی گرافیکی ترمینالی (TUI) داشته باشد.
- در اولین اجرا، به‌صورت مرحله‌ای نقش و تنظیمات را از کاربر بگیرد.
- داده‌ها را با اندازه‌های متنوع منتقل کند و با backpressure سازگار باشد.

## اصول و محدودیت‌ها
- تمرکز روی امنیت قابل‌اتکا (رمزنگاری با کلید مشترک + احراز هویت).
- هیچ هدفی برای پنهان‌سازی/دور زدن پایش شبکه تعریف نمی‌شود.
- فوروارد فقط برای **یک پورت** در هر اجرا.

## تصمیم‌های فنی (قطعی)
- زبان: Rust
- Async runtime: tokio
- رمزنگاری: PSK-based AEAD (بدون TLS)
  - کلید مشترک (PSK) بین Server/Client
  - مشتق‌سازی کلید نشست با HKDF
  - AEAD پیشنهادی: XChaCha20-Poly1305
- پروتکل داخلی: فریم‌بندی باینری با طول + نوع پیام (رمز شده)
  - امکان ارسال payload با اندازه‌های مختلف
  - پشتیبانی از backpressure و محدودیت حافظه
- احراز هویت: همان PSK (challenge/response مبتنی بر HMAC)

## معماری
### Roles
- **Server**: روی ایران، پورت عمومی را باز می‌کند و اتصال ورودی کاربران را می‌گیرد.
- **Client**: روی خارج، به Server متصل می‌شود و ترافیک را به مقصد محلی فوروارد می‌کند.

### Data Flow (تک پورت)
1. Server پورت عمومی را listen می‌کند.
2. Client به Server متصل می‌شود (TLS + احراز هویت).
3. هر اتصال ورودی به Server در یک کانال منطقی به Client هدایت می‌شود.
4. Client اتصال را به مقصد نهایی (مثلاً 127.0.0.1:1414) باز می‌کند و داده را رله می‌کند.

## CLI / TUI
### CLI
```
mytunnel init
mytunnel run --role server
mytunnel run --role client
```

### TUI (منوی گرافیکی ترمینالی)
- انتخاب نقش (Server / Client)
- دریافت مرحله‌ای اطلاعات:
  - آدرس/پورت‌های listen
  - آدرس/پورت مقصد
  - کلید مشترک (PSK)
  - سیاست‌های امنیتی (حداکثر اندازه فریم، نرخ تلاش مجدد)

## فایل‌ها
- `config.toml`
- `logs/`
- `data/` (اگر لازم باشد)

## Milestones
1. طراحی پروتکل فریم‌بندی و message types
2. پیاده‌سازی roleها با TCP + PSK (AEAD)
3. CLI + TUI اولیه
4. مدیریت کانکشن‌ها و backpressure
5. تست‌های یکپارچگی و Load test ساده
6. بسته‌بندی (static build + systemd unit)

## سوالات باز (نیاز به تایید شما)
- طول PSK: 32 بایت (hex 64 کاراکتر) تایید است؟
- سیستم‌عامل هدف فقط Ubuntu 24 است؟
- نرخ و محدودیت اندازه فریم (پیشنهاد: 1MB)؟

## پروتکل پیشنهادی (خلاصه)
- Handshake:
  - ClientHello: نسخه + nonce (24 بایت)
  - ServerHello: nonce (24 بایت) + HMAC(psk, client_nonce || server_nonce)
  - ClientAck: HMAC(psk, server_nonce || client_nonce)
- Session Key:
  - HKDF(psk, salt=client_nonce||server_nonce, info="tunnel-v1")
- Data:
  - فریم‌ها با طول مشخص، سپس AEAD(payload, nonce)
  - nonce افزایشی/تصادفی یکتا در هر سمت
- نیاز به NAT traversal نداریم؟
