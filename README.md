# sing-box Iran Rules

چهار rule-set اختصاصی برای [sing-box](https://github.com/SagerNet/sing-box) — دامنه و IP در فایل‌های جدا:

| فایل | کاربرد | اکشن پیشنهادی |
|---|---|---|
| **`iran-all-domains.srs`** | دامنه‌های ایرانی (با پاک‌سازی پسوند عمومی، سرویس‌های خارجی، تحریم‌شده‌ها) | `direct` |
| **`iran-all-ips.srs`** | رنج IPهای ایرانی (بدون CDN/ابر خارجی و IP خصوصی) | `direct` |
| **`ads-merged-domains.srs`** | دامنه‌های تبلیغات، ردیاب، بدافزار، فیشینگ، ماینر | `reject` |
| **`ads-merged-ips.srs`** | IPهای بدافزار و فیشینگ | `reject` |

فایل‌ها **هر روز ساعت ۳ بامداد به وقت تهران** به‌صورت خودکار از منابع بالادستی ساخته و جایگزین می‌شوند.

> ترتیب رول‌ها مهم است: **اول `ads-merged-*`، بعد `iran-all-*`.** در غیر این صورت تبلیغات ایرانی direct می‌شوند.

> **تغییر از نسخهٔ ۳:** فایل‌های قدیمی `iran-all.srs` و `ads-merged.srs` (دامنه + IP در یک فایل) دیگر ساخته نمی‌شوند. کانفیگ را مطابق نمونهٔ زیر به چهار فایل جدید تغییر دهید.

---

## استفاده در sing-box (آپدیت خودکار)

`update_interval` را `1d` بگذار تا با زمان‌بندی روزانهٔ ریپو هم‌خوان باشد.

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "ads-merged-domains",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Danialrostamani/sing-box-iran-rules/release/ads-merged-domains.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "ads-merged-ips",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Danialrostamani/sing-box-iran-rules/release/ads-merged-ips.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "iran-all-domains",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Danialrostamani/sing-box-iran-rules/release/iran-all-domains.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "iran-all-ips",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Danialrostamani/sing-box-iran-rules/release/iran-all-ips.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      }
    ],
    "rules": [
      { "action": "sniff" },
      { "rule_set": ["ads-merged-domains", "ads-merged-ips"], "action": "reject" },
      { "rule_set": ["iran-all-domains", "iran-all-ips"], "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
```

همین نمونه در [`examples/config.json`](examples/config.json) هم هست.

`iran-all-ips.srs` همان استثناهای دامنه‌ای (Google، Telegram، تبلیغات و …) را دارد؛ یعنی اتصالی که IP مقصدش ایرانی است ولی دامنهٔ sniff‌شده‌اش سرویس خارجی است direct نمی‌شود.

### آدرس‌های جایگزین

اگر `raw.githubusercontent.com` فیلتر بود، در آدرس‌های بالا فقط بخش ابتدایی را عوض کن (نام فایل همان می‌ماند):

| روش | پیشوند آدرس |
|---|---|
| GitHub Release | `https://github.com/Danialrostamani/sing-box-iran-rules/releases/latest/download/` |
| jsDelivr | `https://cdn.jsdelivr.net/gh/Danialrostamani/sing-box-iran-rules@release/` |

`download_detour` را در صورت نیاز روی outbound پروکسی بگذار.

کانفیگ بالا از rule action (`sniff` و `reject`) استفاده می‌کند و نیاز به **sing-box ≥ 1.11** دارد. خود فایل‌های srs نسخهٔ ۱ هستند (sing-box ≥ 1.8)؛ برای نسخهٔ ۲ یا ۳ اسکریپت را با `--rs-version 2` اجرا کن.

---

## فایل‌های خروجی روزانه

شاخهٔ [`release`](../../tree/release) فقط همین‌ها را دارد و هر روز **جایگزین** می‌شود (در Releases هم ۷ نسخهٔ آخر نگه داشته می‌شود):

- `iran-all-domains.srs` / `iran-all-ips.srs` / `ads-merged-domains.srs` / `ads-merged-ips.srs` — باینری sing-box
- همین نام‌ها با پسوند `.json` — همان قوانین، خوانا
- `report.txt` — چه چیزی حذف یا مسدود شد
- `SHA256SUMS`

---

## iran-all-domains / iran-all-ips (direct) چه می‌کنند؟

منابع: Chocolate4U (`geosite-ir`, `geoip-ir`, هاستینگ‌های ایرانی، همهٔ `category-*-ir`)، MetaCubeX، bootmortis/iran-hosted-domains، Loyalsoldier/geoip.

در هر ساخت این‌ها حذف می‌شوند:

1. پسوندهای عمومی Public Suffix List مثل `dyndns.org` / `co.com` (به‌جز `.ir` و `.ایران`)
2. دامنه‌های خارجی شناخته‌شده (Google, Apple, Microsoft, Meta, Telegram, Cloudflare, …)
3. سایت‌های sanctioned که IP ایران را تحریم کرده‌اند
4. رنج IP CDN/ابر خارجی و IP خصوصی/رزرو و IP تزریقی فیلترینگ (`10.10.34.0/24`)
5. هم‌پوشانی با لیست مسدودسازی (تبلیغات ایرانی از direct خارج می‌شوند)
6. تونل‌های Hurricane Electric (`2001:470::/32`) که MaxMind اشتباهاً ایران می‌داند

---

## ads-merged-domains / ads-merged-ips (block) چه می‌کنند؟

سطح پیش‌فرض GitHub Actions: **`normal`**

| سطح | پوشش |
|---|---|
| `lite` | تبلیغات/ردیاب ایرانی + malware/phishing/cryptominers + HaGeZi Light |
| `normal` | lite + HaGeZi Pro-mini + popupads + Fake + TIF-mini + Chocolate4U `@ads` و `category-ads` |
| `full` | HaGeZi Pro + popupads + Fake + TIF-medium + category-ads-all |

دامنه‌های ضروری مثل `googletagmanager.com`، `graph.instagram.com` و دامنهٔ اصلی گوگل/اینستاگرام/گیت‌هاب **مسدود نمی‌شوند** تا سایت‌ها نشکند. ردیاب‌هایی مثل Lucky Orange، FullStory، Hotjar، Clarity مسدودند.

حفاظت: دامنهٔ اصلی سایت‌های ایرانی توسط لیست تبلیغاتی عمومی مسدود نمی‌شود. لیست تهدید (TIF / malware / phishing) اولویت دارد، مگر بانک / پرداخت / دولت / بورس / بیمه.

اگر بخواهی هیچ دامنهٔ ایرانی‌ای به‌خاطر TIF بسته نشود، اسکریپت را با `--trust-ir` اجرا کن.

---

## ساخت دستی

نیازمندی‌ها: `bash`, `curl`, `python3`. اگر `sing-box` نباشد با `--yes` نصب می‌شود.

```bash
git clone https://github.com/Danialrostamani/sing-box-iran-rules.git
cd sing-box-iran-rules
chmod +x iran-one-srs.sh
./iran-one-srs.sh --yes --report
```

گزینه‌ها:

```
./iran-one-srs.sh                     # هر چهار فایل
./iran-one-srs.sh direct              # فقط iran-all-domains و iran-all-ips
./iran-one-srs.sh block --level full  # ads-merged-* با بیشترین پوشش
./iran-one-srs.sh -d /etc/sing-box --yes --report
./iran-one-srs.sh --trust-ir          # تهدید هم سایت ایرانی را نبندد
./iran-one-srs.sh --rs-version 2      # برای sing-box ≥ 1.10
./iran-one-srs.sh --no-ipv6
```

آپدیت دستی از گیت‌هاب: Actions → **Update rule-sets** → Run workflow.

---

## مجوز

GPL-3.0. داده‌های بالادستی متعلق به پروژه‌های اصلی است؛ جزئیات در [CREDITS.md](CREDITS.md).
