# 🦁 MidONe Scanner SK v6.1
### Shir Khorshid Ultimate CDN IP Scanner

A smart multi-stage CDN IP scanner built for the CDN Fronting feature of Shir Khorshid app.

> 📣 **Telegram:** [@mmdrlx](https://t.me/mmdrlx)

---

یک اسکنر فوق‌پیشرفته چندرشته‌ای برای سنجش کیفیت، پایداری و پهنای باند واقعی آی‌پی‌های تمیز جهت استفاده در شیر خورشید.

---

## ✨ Features / ویژگی‌ها

- 🔍 **CDN Auto-Detection** — تشخیص خودکار Cloudflare, Akamai, Google, Amazon, Azure, Fastly
- 🧪 **Reliability x5** — هر آی‌پی ۵ بار تست می‌شه، حداقل ۳/۵ = پایدار
- ⚡ **Real Bandwidth Test** — سنجش پهنای باند واقعی، نه پینگ ساده
- 🚨 **Throttle Detection** — تشخیص خفقان ترافیک توسط فایروال
- 🧠 **Smart SNI Ordering** — SNI مناسب هر CDN اول تست می‌شه
- 📊 **Advanced Scoring** — سرعت ۵۵٪ + پینگ ۲۰٪ + جیتر ۱۰٪ + پایداری ۱۵٪
- 📋 **Clean IP List** — لیست آماده برای کپی مستقیم توی اپ

---

## 📱 Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install python git -y
git clone https://github.com/YOUR_USERNAME/shirkhorshid-scanner.git
cd shirkhorshid-scanner
python scanner.py
```

---

## 💻 Windows

```bash
git clone https://github.com/YOUR_USERNAME/shirkhorshid-scanner.git
cd shirkhorshid-scanner
python scanner.py
```

---

## 🎮 How to Use / روش استفاده

```
[1] Simple Scan  — سریع، SNI خودکار google.com
[2] Auto-SNI     — پیشرفته، تشخیص CDN + همه SNI ها
```

IP ها رو پیست کن ← اینتر خالی بزن ← اسکن شروع میشه

### نتیجه رو کجا بذاریم؟
```
شیر خورشید ← Settings ← CDN Fronting
CDN edge IPs ← IP های TOP رو پیست کن
CDN SNI hostname ← SNI پیشنهادی رو وارد کن
```

---

## 📊 Grading System

| Grade | Speed | Meaning |
|-------|-------|---------|
| S *** | +300 KB/s | Excellent |
| A **  | +200 KB/s | Great ✅ |
| B *   | +100 KB/s | Good |
| C     | +50 KB/s  | Weak |
| D     | -50 KB/s  | Bad |
| THROTTLED | — | ISP is limiting this IP |

---

## 🌐 Supported CDNs

| CDN | SNIs |
|-----|------|
| Cloudflare | speed.cloudflare.com, cloudflare.com |
| Akamai | a248.e.akamai.net, a77, a104, a184, ds-aksb, ak |
| Google | fonts.googleapis.com, google.com |
| Amazon | d1.cloudfront.net |
| Azure | ajax.aspnetcdn.com |
| Fastly | global.fastly.net |
| Iranian | aparat.com, snapp.ir, digikala.com, telewebion.com, varzesh3.com, bmi.ir |

---

## ⚙️ Configuration

```python
CFG = {
    "threads":            30,    # concurrent threads
    "connect_timeout":    2.5,   # connection timeout
    "test_duration":      5.0,   # bandwidth test duration
    "throttle_threshold": 0.40,  # throttle detection threshold
    "reliability_tries":  5,     # reliability test count
    "reliability_min":    3,     # minimum pass out of 5
}
```

---

## ❓ FAQ

**چرا بعضی IP ها توی اسکن قبول میشن ولی توی اپ وصل نمیشن؟**
این اسکنر Throttle Detection داره — IP هایی که ISP بعداً خفه‌شون می‌کنه با `[THR]` علامت می‌زنه. فقط IP های بدون این علامت رو استفاده کن.

**کدوم Mode بهتره؟**
برای نتیجه دقیق‌تر Mode 2 — برای سرعت بیشتر Mode 1.

**چند تا IP وارد کنم؟**
بین ۲۰ تا ۱۰۰ IP ایده‌آله.

---

## 📣 Channel / کانال

برای دریافت IP های تازه و آپدیت‌های اسکنر:

**➡️ Telegram: [@mmdrlx](https://t.me/mmdrlx)**
