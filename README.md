# sing-box Iran Rules

دو rule-set اختصاصی برای [sing-box](https://github.com/SagerNet/sing-box):

| فایل | کاربرد | اکشن پیشنهادی |
|---|---|---|
| **`iran-all.srs`** | سایت‌ها و IPهای ایرانی (با پاک‌سازی CDN خارجی، پسوند عمومی، تحریم‌شده‌ها) | `direct` |
| **`ads-merged.srs`** | تبلیغات، ردیاب، بدافزار، فیشینگ، ماینر | `reject` |

فایل‌ها **هر دوشنبه** به‌صورت خودکار از منابع بالادستی ساخته و جایگزین می‌شوند.

> ترتیب رول‌ها مهم است: **اول `ads-merged`، بعد `iran-all`.** در غیر این صورت تبلیغات ایرانی direct می‌شوند.

---

## استفاده در sing-box (آپدیت خودکار)

`USER` را با نام کاربری گیت‌هاب خودت عوض کن. `update_interval` را `7d` بگذار تا با زمان‌بندی ریپو هم‌خوان باشد.

```json
{
  "route": {
    "rule_set": [
      {
        "tag": "ads-merged",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Danialrostamani/sing-box-iran-rules/release/ads-merged.srs",
        "download_detour": "direct",
        "update_interval": "7d"
      },
      {
        "tag": "iran-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/Danialrostamani/sing-box-iran-rules/release/iran-all.srs",
        "download_detour": "direct",
        "update_interval": "7d"
      }
    ],
    "rules": [
      { "action": "sniff" },
      { "rule_set": "ads-merged", "action": "reject" },
      { "rule_set": "iran-all", "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
```

نمونهٔ کامل‌تر در [`examples/config.json`](examples/config.json) است.

### آدرس‌های جایگزین

اگر `raw.githubusercontent.com` فیلتر بود:

| روش | iran-all | ads-merged |
|---|---|---|
| GitHub Release | `https://github.com/Danialrostamani/sing-box-iran-rules/releases/latest/download/iran-all.srs` | `.../ads-merged.srs` |
| jsDelivr | `https://cdn.jsdelivr.net/gh/Danialrostamani/sing-box-iran-rules@release/iran-all.srs` | `.../ads-merged.srs` |

`download_detour` را در صورت نیاز روی outbound پروکسی بگذار.

نیاز به **sing-box ≥ 1.8** (rule-set نسخهٔ ۱). برای نسخهٔ ۲ یا ۳ اسکریپت را با `--rs-version 2` اجرا کن.

---

## فایل‌های خروجی هر هفته

شاخهٔ [`release`](../../tree/release) فقط همین‌ها را دارد و هر هفته **جایگزین** می‌شود:

- `iran-all.srs` / `ads-merged.srs` — باینری sing-box
- `iran-all.json` / `ads-merged.json` — همان قوانین، خوانا
- `report.txt` — چه چیزی حذف یا مسدود شد
- `SHA256SUMS`

---

## iran-all (direct) چه می‌کند؟

منابع: Chocolate4U (`geosite-ir`, `geoip-ir`, هاستینگ‌های ایرانی، همهٔ `category-*-ir`)، MetaCubeX، bootmortis/iran-hosted-domains، Loyalsoldier/geoip.

در هر ساخت این‌ها حذف می‌شوند:

1. پسوندهای عمومی Public Suffix List مثل `dyndns.org` / `co.com` (به‌جز `.ir` و `.ایران`)
2. دامنه‌های خارجی شناخته‌شده (Google, Apple, Microsoft, Meta, Telegram, Cloudflare, …)
3. سایت‌های sanctioned که IP ایران را تحریم کرده‌اند
4. رنج IP CDN/ابر خارجی و IP خصوصی/رزرو و IP تزریقی فیلترینگ (`10.10.34.0/24`)
5. هم‌پوشانی با لیست مسدودسازی (تبلیغات ایرانی از direct خارج می‌شوند)
6. تونل‌های Hurricane Electric (`2001:470::/32`) که MaxMind اشتباهاً ایران می‌داند

---

## ads-merged (block) چه می‌کند؟

سطح پیش‌فرض GitHub Actions: **`normal`**

| سطح | پوشش |
|---|---|
| `lite` | تبلیغات/ردیاب ایرانی + malware/phishing/cryptominers + HaGeZi Light |
| `normal` | lite + HaGeZi Pro-mini + HaGeZi TIF-mini |
| `full` | HaGeZi Pro + TIF-medium + category-ads-all |

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
./iran-one-srs.sh                     # هر دو فایل
./iran-one-srs.sh direct              # فقط iran-all
./iran-one-srs.sh block --level full  # ads-merged با بیشترین پوشش
./iran-one-srs.sh -d /etc/sing-box --yes --report
./iran-one-srs.sh --trust-ir          # تهدید هم سایت ایرانی را نبندد
./iran-one-srs.sh --rs-version 2      # برای sing-box ≥ 1.10
./iran-one-srs.sh --no-ipv6
```

آپدیت دستی از گیت‌هاب: Actions → **Update rule-sets** → Run workflow.

---

## مجوز

GPL-3.0. داده‌های بالادستی متعلق به پروژه‌های اصلی است؛ جزئیات در [CREDITS.md](CREDITS.md).
