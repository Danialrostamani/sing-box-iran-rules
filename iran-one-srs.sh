#!/usr/bin/env bash
# ============================================================================
#  iran-one-srs.sh  v3.0  —  ساخت چهار فایل srs برای sing-box (دامنه و IP جدا)
#  ----------------------------------------------------------------------------
#    iran-all-domains.srs    ← دامنه‌های ایرانی که باید «direct» شوند (با بررسی دقیق)
#    iran-all-ips.srs        ← رنج IPهای ایرانی که باید «direct» شوند
#    ads-merged-domains.srs  ← دامنه‌های تبلیغات، ردیاب، بدافزار، فیشینگ، ماینر  («reject»)
#    ads-merged-ips.srs      ← IPهای بدافزار/فیشینگ  («reject»)
#
#  ┌─ iran-all-*.srs (direct) ─────────────────────────────────────────────────┐
#  │ منابع: Chocolate4U (geosite-ir, geoip-ir, هاستینگ‌های ایرانی،         │
#  │        همهٔ category-*-ir با جستجوی خودکار) + MetaCubeX (ir)           │
#  │        + bootmortis/iran-hosted-domains + Loyalsoldier/geoip           │
#  │ بررسی‌های خودکار در هر اجرا:                                          │
#  │   ۱. حذف پسوندهای عمومی (Public Suffix List) مثل dyndns.org, co.com   │
#  │      که یعنی «کل یک سرویس جهانی» — فقط .ir و .ایران مجازند            │
#  │   ۲. حذف دامنه‌های خارجیِ شناخته‌شده (DENY_DIRECT)                    │
#  │   ۳. مستثنا کردن هر دامنه از لیست سرویس‌های خارجی                      │
#  │      (Google, Apple, Microsoft, Meta, Telegram, Cloudflare, ...)      │
#  │      و لیست sanctioned (سایت‌هایی که IP ایران را تحریم کرده‌اند)       │
#  │   ۴. کم کردن رنج IPهای CDN/ابرهای خارجی (Cloudflare, Google, AWS, ...) │
#  │      و IPهای خصوصی/رزرو از رنج‌های ایران                              │
#  │   ۵. مستثنا کردن تبلیغات/بدافزار/فیشینگ (هم‌پوشانی با ads-merged-*.srs)     │
#  │   ۶. (--strict) بررسی DNS: دامنه‌ای که به IP غیرایرانی resolve شود     │
#  │      حذف می‌شود — این گزینه را داخل ایران اجرا کنید                   │
#  └───────────────────────────────────────────────────────────────────────┘
#  ┌─ ads-merged-*.srs (reject) ───────────────────────────────────────────────┐
#  │ lite  : تبلیغات/ردیاب ایرانی + malware/phishing/cryptominers          │
#  │         + HaGeZi Light                                                │
#  │ normal: lite + HaGeZi Pro-mini + popupads + Fake + TIF-mini           │
#  │         + Chocolate4U google/facebook/amazon/apple/microsoft/yandex@ads│
#  │         + category-ads   [پیش‌فرض GitHub Actions]                     │
#  │ full  : HaGeZi Pro + popupads + Fake + TIF-medium + category-ads-all  │
#  │ محافظت: دامنهٔ اصلی سایت‌های ایرانی (category-*-ir) توسط لیست‌های     │
#  │   تبلیغاتی عمومی مسدود نمی‌شود (HaGeZi مثلاً mcinext.com و mihanblog را │
#  │   دارد). لیست‌های تهدید (TIF، malware، phishing) اولویت دارند، مگر     │
#  │   برای بانک/پرداخت/دولت/بورس/بیمه که همیشه آزاد می‌مانند.             │
#  │ بررسی نهایی: فایل‌های خروجی decompile و صحت نوع (دامنه/IP) چک می‌شود. │
#  └───────────────────────────────────────────────────────────────────────┘
#
#  استفاده:
#     ./iran-one-srs.sh                     # هر چهار فایل در پوشهٔ فعلی
#     ./iran-one-srs.sh direct              # فقط iran-all-domains.srs و iran-all-ips.srs
#     ./iran-one-srs.sh block --level full  # فقط ads-merged-*.srs با بیشترین پوشش
#     ./iran-one-srs.sh -d /etc/sing-box --yes --report
#
#  گزینه‌ها:
#     -d, --dir DIR       پوشهٔ خروجی (پیش‌فرض: پوشهٔ فعلی)
#     --level L           سطح مسدودسازی: lite | normal | full  (پیش‌فرض normal)
#     --strict            بررسی DNS دامنه‌های غیر .ir (کند؛ داخل ایران اجرا شود)
#     --report            گزارش کامل موارد حذف‌شده → report.txt
#     --no-ipv6           IPv6 اضافه نشود
#     --trust-ir          لیست‌های تهدید (TIF/malware) هم نتوانند دامنهٔ اصلی سایت‌های ایرانی را ببندند
#     --rs-version N      نسخهٔ rule-set خروجی: 1 (sing-box ≥1.8، پیش‌فرض) | 2 (≥1.10) | 3 (≥1.11)
#     --mirror URL        آینه برای وقتی گیت‌هاب کند/فیلتر است
#     --sing-box PATH     مسیر باینری sing-box
#     --yes               اگر sing-box نبود، بدون سوال نصب شود (~/.local/bin)
#     -h, --help          راهنما
#
#  نیازمندی‌ها: bash، curl، python3 (git اختیاری). نیازی به توکن گیت‌هاب نیست.
# ============================================================================

set -uo pipefail
VERSION="3.0.0"

MODE="all"
OUT_DIR="."
LEVEL="normal"
STRICT=0
REPORT=0
WITH_IPV6=1
RS_VERSION=1
MIRROR="${MIRROR:-}"
SING_BOX_BIN="${SING_BOX_BIN:-}"
ASSUME_YES=0

# ------------------------------- منابع --------------------------------------
CHOCO_REPO="Chocolate4U/Iran-sing-box-rules"
CHOCO_BRANCH="rule-set"
CHOCO_RAW="https://raw.githubusercontent.com/$CHOCO_REPO/$CHOCO_BRANCH"
META_RAW="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo"
BOOT_DL="https://github.com/bootmortis/iran-hosted-domains/releases/latest/download"
LS_IP="https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ir.txt"
PSL_URL="https://publicsuffix.org/list/public_suffix_list.dat"
PSL_MIRROR="https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat"
HAGEZI="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard"
PBLOCK="https://raw.githubusercontent.com/MasterKia/PersianBlocker/main"

# --- direct: رول‌های ثابت + جستجوی خودکار category-*-ir ---
DIRECT_RULES=(geosite-ir geoip-ir geoip-arvancloud geoip-derakcloud geoip-iranserver geoip-parspack)
DIRECT_META=("geoip/ir.srs" "geosite/category-ir.srs")
DISCOVER_RE='^geo(site|ip)-(.+-)?ir$'
DISCOVER_EXCLUDE='(^|-)(ads?|malware|phishing|tracker|trackernetwork|security|injected)(-|$)'

# --- لیست سرویس‌های خارجی که هرگز نباید direct شوند ---
FOREIGN_SITES=(geosite-google geosite-apple geosite-microsoft geosite-amazon geosite-cloudflare
  geosite-meta geosite-facebook geosite-instagram geosite-whatsapp geosite-telegram geosite-twitter
  geosite-youtube geosite-github geosite-openai geosite-netflix geosite-spotify geosite-tiktok
  geosite-discord geosite-sanctioned)
FOREIGN_IPS=(geoip-cloudflare geoip-cloudfront geoip-google geoip-amazon geoip-fastly geoip-gcore
  geoip-microsoft geoip-facebook geoip-telegram geoip-twitter geoip-netflix geoip-openai
  geoip-github geoip-oracle geoip-digitalocean geoip-linode
  geoip-irgfw-other-injected-ips)   # IPهای جعلی که فیلترینگ تزریق می‌کند
# رنج‌های ثابتی که هرگز نباید direct شوند (حتی اگر GeoIP آن‌ها را «ایران» بداند)
FOREIGN_STATIC_IPS=(2001:470::/32)   # تونل‌های Hurricane Electric (سرورشان خارج از ایران است)
# دسته‌هایی که حتی لیست‌های تهدید هم حق مسدود کردن دامنهٔ اصلی‌شان را ندارند
CRITICAL_CATEGORIES='category-(bank|payment|gov|bourse|insurance)-ir'
# دامنه‌های خارجی که در لیست‌های ایران پیدا شدند (سرویس جهانی / هاست رایگان خارجی)
DENY_DIRECT=(co.com dyndns.org selfip.com ddnsguru.com sells-it.net epizy.com webstarts.com
  lumen5.com info.com salamair.com 3cx.eu somee.com speedcheckerapi.com)
# همیشه direct بمانند (حتی اگر در لیست تبلیغات/خارجی باشند)
KEEP_DIRECT=(zarin.link sabaidea.cloud liara.run)

# دامنه‌هایی که هرگز reject نمی‌شوند (سایت را نمی‌شکنند).
# NEVER_BLOCK: خودش و زیردامنه‌ها.  NEVER_BLOCK_EXACT: فقط همان دامنه (نه ads.google.com).
NEVER_BLOCK=(
  googletagmanager.com        # خیلی از سایت‌ها به GTM وابسته‌اند
  googletagmanager-cn.com
  graph.instagram.com         # API اینستاگرام
  graph-fallback.instagram.com
  tracker.gg                  # سایت آمار بازی، ردیاب تبلیغاتی نیست
)
NEVER_BLOCK_EXACT=(
  google.com youtube.com gmail.com wikipedia.org wikimedia.org
  facebook.com instagram.com whatsapp.com messenger.com
  github.com cloudflare.com apple.com microsoft.com amazon.com
  telegram.org twitter.com tiktok.com netflix.com spotify.com
)

# --- block: دامنه‌های دستی که «همیشه» مسدود می‌شوند (بالاترین اولویت) ---
# هر دامنه‌ای اضافه کنید، خودش و همهٔ زیردامنه‌هایش مسدود می‌شود.
EXTRA_BLOCK=(
  ad.doubleclick.net          # تبلیغات گوگل (HaGeZi عمداً آزادش گذاشته)
  adservice.google.com        # تبلیغات گوگل (فقط در HaGeZi Pro++ هست)
  fullstory.com               # session replay
  smartlook.com
  contentsquare.com
  logrocket.com
  glassbox.com
  segment.io
)

# --- block: منابع مسدودسازی ---
BLOCK_IR_CHOCO=(geosite-ads geosite-category-ads-ir)                     # تبلیغات ایرانی
THREAT_CHOCO=(geosite-malware geosite-phishing geosite-cryptominers geoip-malware geoip-phishing)  # تهدید (بدون محافظت)
BLOCK_IR_TEXT=("$BOOT_DL/surge_domainset_ads.txt"
  "$PBLOCK/PersianBlockerAds-Domains.txt"
  "$PBLOCK/PersianBlockerTrackers-Domains.txt"
  "$PBLOCK/PersianBlockerHosts.txt")

# ------------------------------- ظاهر ---------------------------------------
if [ -t 2 ]; then C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_C=$'\e[36m'; C_0=$'\e[0m'
else C_G=""; C_Y=""; C_R=""; C_C=""; C_0=""; fi
log()  { printf '%s\n' "${C_C}[+]${C_0} $*" >&2; }
ok()   { printf '%s\n' "${C_G}[✓]${C_0} $*" >&2; }
warn() { printf '%s\n' "${C_Y}[!]${C_0} $*" >&2; }
die()  { printf '%s\n' "${C_R}[✗]${C_0} $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
usage() { awk '/^# =+$/{if(++n==2)exit;next} n==1' "$0" | sed 's/^# \{0,2\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    all|direct|block) MODE="$1" ;;
    -d|--dir)    OUT_DIR="${2:?}"; shift ;;
    --level)     LEVEL="${2:?}"; shift ;;
    --strict)    STRICT=1 ;;
    --report)    REPORT=1 ;;
    --no-ipv6)   WITH_IPV6=0 ;;
    --rs-version) RS_VERSION="${2:?}"; shift ;;
    --trust-ir)  CRITICAL_CATEGORIES='category(-.+)?-ir' ;;
    --mirror)    MIRROR="${2:?}"; shift ;;
    --sing-box)  SING_BOX_BIN="${2:?}"; shift ;;
    --yes|-y)    ASSUME_YES=1 ;;
    -h|--help)   usage ;;
    --version)   echo "$VERSION"; exit 0 ;;
    *) die "گزینهٔ ناشناخته: $1  (راهنما: --help)" ;;
  esac
  shift
done
case "$LEVEL" in lite|normal|full) ;; *) die "--level باید lite یا normal یا full باشد." ;; esac
case "$RS_VERSION" in 1|2|3) ;; *) die "--rs-version باید 1 یا 2 یا 3 باشد." ;; esac

case "$LEVEL" in
  lite)   BLOCK_TEXT=("$HAGEZI/light-onlydomains.txt")
          THREAT_TEXT=()
          BLOCK_EXTRA_CHOCO=() ;;
  normal) BLOCK_TEXT=("$HAGEZI/pro.mini-onlydomains.txt" "$HAGEZI/popupads-onlydomains.txt")
          THREAT_TEXT=("$HAGEZI/tif.mini-onlydomains.txt" "$HAGEZI/fake-onlydomains.txt")
          BLOCK_EXTRA_CHOCO=(geosite-category-ads geosite-google@ads geosite-facebook@ads
            geosite-amazon@ads geosite-apple@ads geosite-microsoft@ads geosite-yandex@ads) ;;
  full)   BLOCK_TEXT=("$HAGEZI/pro-onlydomains.txt" "$HAGEZI/popupads-onlydomains.txt")
          THREAT_TEXT=("$HAGEZI/tif.medium-onlydomains.txt" "$HAGEZI/fake-onlydomains.txt")
          BLOCK_EXTRA_CHOCO=(geosite-category-ads-all geosite-google@ads geosite-facebook@ads
            geosite-amazon@ads geosite-apple@ads geosite-microsoft@ads geosite-yandex@ads) ;;
esac

have curl    || die "curl نصب نیست."
have python3 || die "python3 نصب نیست."

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t iransrs)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/dl" "$TMP/j"
MANIFEST="$TMP/manifest.tsv"; : > "$MANIFEST"

mirrorize() {
  if [ -n "$MIRROR" ]; then
    case "$1" in https://github.com/*|https://raw.githubusercontent.com/*)
      printf '%s%s' "${MIRROR%/}/" "$1"; return ;; esac
  fi
  printf '%s' "$1"
}
fetch() { # fetch <url> <out>
  local url a; url="$(mirrorize "$1")"
  for a in 1 2 3; do
    curl -fsL --connect-timeout 20 --max-time 300 -o "$2" "$url" && [ -s "$2" ] && return 0
    sleep "$a"
  done
  return 1
}
is_srs() { [ "$(od -An -tx1 -N3 "$1" 2>/dev/null | tr -d ' \n')" = "535253" ]; }
sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ----------------------------- sing-box -------------------------------------
install_sing_box() {
  local os arch tag url
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;;
    *) die "sing-box را دستی نصب کنید و با --sing-box مسیرش را بدهید." ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;;
    armv7*|armv6*) arch=armv7 ;; i386|i686) arch=386 ;;
    *) die "معماری $(uname -m) پشتیبانی نمی‌شود." ;; esac
  tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$(mirrorize https://github.com/SagerNet/sing-box/releases/latest)")"
  tag="${tag##*/}"
  case "$tag" in v[0-9]*) ;; *) die "تشخیص آخرین نسخهٔ sing-box ناموفق بود." ;; esac
  log "نصب sing-box $tag ($os-$arch) ..."
  url="https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-$os-$arch.tar.gz"
  fetch "$url" "$TMP/sb.tgz" || die "دانلود sing-box ناموفق بود."
  tar -xzf "$TMP/sb.tgz" -C "$TMP" || die "استخراج sing-box ناموفق بود."
  mkdir -p "$HOME/.local/bin"
  mv "$TMP/sing-box-${tag#v}-$os-$arch/sing-box" "$HOME/.local/bin/sing-box"
  chmod +x "$HOME/.local/bin/sing-box"
  ok "sing-box در ~/.local/bin/sing-box نصب شد"
  SING_BOX_BIN="$HOME/.local/bin/sing-box"
}
ensure_sing_box() {
  if [ -n "$SING_BOX_BIN" ] && [ -x "$SING_BOX_BIN" ]; then return; fi
  if have sing-box; then SING_BOX_BIN="$(command -v sing-box)"; return; fi
  if [ -x "$HOME/.local/bin/sing-box" ]; then SING_BOX_BIN="$HOME/.local/bin/sing-box"; return; fi
  if [ "$ASSUME_YES" -ne 1 ]; then
    printf '%s' "${C_Y}[?]${C_0} sing-box پیدا نشد. نصبش کنم؟ [y/N] " >&2
    read -r ans || ans=""
    case "$ans" in [yY]*) ;; *) die "بدون sing-box نمی‌شود srs ساخت (یا از --yes استفاده کنید)." ;; esac
  fi
  install_sing_box
}

# ------------------------ دانلود موازی + ثبت در manifest --------------------
QUEUE="$TMP/queue.tsv"; : > "$QUEUE"
# add <group> <kind: srs|text|ip|psl> <name> <url>
add() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(mirrorize "$4")" >> "$QUEUE"; }

download_all() {
  # دانلود موازی (۸ همزمان) با curl
  awk -F'\t' '{print $4"\t'"$TMP"'/dl/"$1"__"$3}' "$QUEUE" | sort -u > "$TMP/urls.tsv"
  tr '\t' '\n' < "$TMP/urls.tsv" | xargs -n 2 -P 8 sh -c \
    'for i in 1 2 3; do curl -fsL --connect-timeout 20 --max-time 300 -o "$1" "$0" && [ -s "$1" ] && exit 0; sleep $i; done; rm -f "$1"; exit 0'
  local g k n u f
  while IFS="$(printf '\t')" read -r g k n u; do
    f="$TMP/dl/${g}__${n}"
    if [ ! -s "$f" ]; then printf '    %-46s ✗ (دریافت نشد)\n' "$g/$n" >&2; continue; fi
    if [ "$k" = "srs" ]; then
      if is_srs "$f" && "$SING_BOX_BIN" rule-set decompile "$f" -o "$TMP/j/${g}__${n}.json" >/dev/null 2>&1; then
        printf '%s\t%s\t%s\t%s\n' "$g" json "$n" "$TMP/j/${g}__${n}.json" >> "$MANIFEST"
      else printf '    %-46s ✗ (srs نامعتبر)\n' "$g/$n" >&2; continue; fi
    else
      printf '%s\t%s\t%s\t%s\n' "$g" "$k" "$n" "$f" >> "$MANIFEST"
    fi
  done < "$QUEUE"
}

discover_direct() {
  local list="$TMP/tree.txt"; : > "$list"
  if have git && git clone -q --depth 1 --filter=blob:none --no-checkout -b "$CHOCO_BRANCH" \
       "$(mirrorize "https://github.com/$CHOCO_REPO.git")" "$TMP/repo" 2>/dev/null; then
    git -C "$TMP/repo" ls-tree --name-only HEAD > "$list"
  fi
  if [ ! -s "$list" ]; then
    curl -fsL "https://api.github.com/repos/$CHOCO_REPO/git/trees/$CHOCO_BRANCH" 2>/dev/null \
      | python3 -c 'import json,sys
try: [print(t["path"]) for t in json.load(sys.stdin).get("tree",[])]
except Exception: pass' > "$list"
  fi
  {
    printf '%s\n' "${DIRECT_RULES[@]}"
    if [ -s "$list" ]; then
      grep -E '\.srs$' "$list" | sed 's/\.srs$//' | grep -E -- "$DISCOVER_RE"
    else
      warn "لیست مخزن گرفته نشد؛ از لیست داخلی استفاده می‌شود."
      printf 'geosite-category-%s-ir\n' bank bourse education forums gov insurance media \
        news payment scholar shopping social-media tech travel
      echo geosite-category-ir
    fi
  } | grep -Ev -- "$DISCOVER_EXCLUDE" | awk 'NF && !seen[$0]++'
}

# ================================ اجرا ======================================
ensure_sing_box
log "sing-box: $("$SING_BOX_BIN" version 2>/dev/null | head -1)  |  حالت: $MODE  |  سطح مسدودسازی: $LEVEL"
mkdir -p "$OUT_DIR" || die "ساخت پوشهٔ خروجی ناموفق بود: $OUT_DIR"

log "۱) جستجوی منابع ..."
n_direct=0
while IFS= read -r r; do
  [ -n "$r" ] || continue
  add direct srs "$r" "$CHOCO_RAW/$r.srs"; n_direct=$((n_direct + 1))
done <<EOF
$(discover_direct)
EOF
for m in "${DIRECT_META[@]}"; do add direct srs "metacube-$(echo "$m" | tr '/' '-')" "$META_RAW/$m"; done
add direct text "bootmortis-domains" "$BOOT_DL/domains.txt"
add sha raw "bootmortis-domains.sha256" "$BOOT_DL/domains.txt.sha256"
add direct ip   "loyalsoldier-ir" "$LS_IP"
for r in "${FOREIGN_SITES[@]}"; do add foreign srs "$r" "$CHOCO_RAW/$r.srs"; done
for r in "${FOREIGN_IPS[@]}";   do add foreign srs "$r" "$CHOCO_RAW/$r.srs"; done
add psl psl "public-suffix-list" "$PSL_URL"
# block همیشه دانلود می‌شود (برای پاک‌سازی iran-all-*.srs هم لازم است)
for r in "${BLOCK_IR_CHOCO[@]}"; do add blockir srs "$r" "$CHOCO_RAW/$r.srs"; done
for u in "${BLOCK_IR_TEXT[@]}";  do add blockir text "$(basename "$u")" "$u"; done
for r in ${BLOCK_EXTRA_CHOCO[@]+"${BLOCK_EXTRA_CHOCO[@]}"}; do add block srs "$r" "$CHOCO_RAW/$r.srs"; done
for u in "${BLOCK_TEXT[@]}";     do add block text "hagezi-$(basename "$u")" "$u"; done
for r in "${THREAT_CHOCO[@]}";   do add threat srs "$r" "$CHOCO_RAW/$r.srs"; done
for u in ${THREAT_TEXT[@]+"${THREAT_TEXT[@]}"}; do add threat text "hagezi-$(basename "$u")" "$u"; done
ok "$n_direct رول ایرانی + $(( ${#FOREIGN_SITES[@]} + ${#FOREIGN_IPS[@]} )) لیست کنترل خارجی + $(grep -Ec '^(block|threat)' "$QUEUE") لیست مسدودسازی"

log "۲) دانلود موازی ($(wc -l < "$QUEUE" | tr -d ' ') فایل) ..."
download_all
# PSL: اگر publicsuffix.org در دسترس نبود از گیت‌هاب
if ! grep -q $'^psl\t' "$MANIFEST"; then
  fetch "$PSL_MIRROR" "$TMP/dl/psl2" && printf 'psl\tpsl\tpsl\t%s\n' "$TMP/dl/psl2" >> "$MANIFEST" \
    || warn "لیست Public Suffix دریافت نشد؛ بررسی ۱ انجام نمی‌شود."
fi
# تأیید SHA256 دامنه‌های bootmortis
dom="$TMP/dl/direct__bootmortis-domains"; sha="$TMP/dl/sha__bootmortis-domains.sha256"
if [ -s "$dom" ] && [ -s "$sha" ]; then
  if [ "$(awk '{print $1; exit}' "$sha")" = "$(sha256_of "$dom")" ]; then ok "SHA256 دامنه‌های bootmortis تأیید شد"
  else warn "SHA256 دامنه‌های bootmortis مطابقت ندارد؛ این منبع رد شد."
       grep -v $'\tbootmortis-domains\t' "$MANIFEST" > "$MANIFEST.t"; mv "$MANIFEST.t" "$MANIFEST"; fi
fi
ok "$(grep -vc $'^sha\t' "$MANIFEST" | tr -d ' ') فایل آماده شد"

# ----------------------------- موتور پردازش ---------------------------------
cat > "$TMP/engine.py" <<'PYEOF'
import bisect, ipaddress, json, os, re, socket, sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

manifest, outdir, mode = sys.argv[1:4]
E = os.environ
STRICT, REPORT = E.get("STRICT") == "1", E.get("REPORT") == "1"
WITH_V6 = E.get("WITH_IPV6", "1") == "1"
DENY = set(E.get("DENY_DIRECT", "").split())
KEEP = set(E.get("KEEP_DIRECT", "").split())
NEVER = {x.strip(".").lower() for x in E.get("NEVER_BLOCK", "").split() if x.strip()}
NEVER_EXACT = {x.strip(".").lower() for x in E.get("NEVER_BLOCK_EXACT", "").split() if x.strip()}
def is_never(c):
    c = c.strip(".").lower()
    if c in NEVER_EXACT or c in NEVER:
        return True
    return any(c.endswith("." + n) for n in NEVER)

RS_VERSION = int(E.get("RS_VERSION", "1"))
CRIT_RE = re.compile(E.get("CRITICAL_CATEGORIES", r"category-(bank|payment|gov|bourse|insurance)-ir"))
STATIC_FOREIGN_IP = []
for x in E.get("FOREIGN_STATIC_IPS", "").split():
    try: STATIC_FOREIGN_IP.append(ipaddress.ip_network(x, strict=False))
    except ValueError: pass
IRTLD = {"ir", "xn--mgba3a4f16a"}
DOMRE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
def say(*a): print("   ", *a, file=sys.stderr)
def fa(n): return f"{n:,}"

# ---------------- ساختار داده ----------------
class DS:
    def __init__(s): s.suf, s.dom, s.kw, s.rx, s.ip = set(), set(), set(), set(), []
    def update(s, o):
        s.suf |= o.suf; s.dom |= o.dom; s.kw |= o.kw; s.rx |= o.rx; s.ip += o.ip

def L(v): return v if isinstance(v, list) else [v]
def norm(d): return d.strip().strip(".").lower() if not d.startswith(".") else "." + d.strip().strip(".").lower()

INVALID = set()   # ورودی‌هایی که دامنهٔ معتبر نبودند (IP، کاراکتر غیرمجاز، ...)
def valid_dom(d):
    c = d.lstrip(".")
    if c in IRTLD or DOMRE.match(c): return True
    try:
        ipaddress.ip_address(c); INVALID.add(c + "  (IP در لیست دامنه)")
    except ValueError: INVALID.add(c)
    return False
def load_json(path):
    ds = DS()
    for r in json.load(open(path, encoding="utf-8")).get("rules", []):
        if r.get("type") == "logical" or r.get("invert"): continue
        ds.suf |= {norm(x) for x in L(r.get("domain_suffix", [])) if x.strip() and valid_dom(norm(x))}
        ds.dom |= {norm(x) for x in L(r.get("domain", [])) if x.strip() and valid_dom(norm(x))}
        ds.kw |= {x.strip().lower() for x in L(r.get("domain_keyword", [])) if x.strip()}
        ds.rx |= {x.strip() for x in L(r.get("domain_regex", [])) if x.strip()}
        for x in L(r.get("ip_cidr", [])):
            try: ds.ip.append(ipaddress.ip_network(x.strip(), strict=False))
            except ValueError: pass
    return ds

def load_text(path):
    """دامنه‌ها: plain / .domain / *.domain / ||domain^ / hosts (0.0.0.0 d)"""
    ds = DS()
    for line in open(path, encoding="utf-8", errors="ignore"):
        l = line.strip()
        if not l or l[0] in "#![" or l.startswith("@@"): continue
        l = l.split("#", 1)[0].strip()
        exact = False
        if l.startswith("||"):
            if not l.endswith("^") or "$" in l or "/" in l: continue
            l = l[2:-1]
        elif " " in l or "\t" in l:
            p = l.split()
            if p[0] not in ("0.0.0.0", "127.0.0.1", "::", "::1") or len(p) < 2: continue
            l, exact = p[1], True
        if l.startswith("*."): l = l[2:]
        l = l.strip(".").lower()
        if not DOMRE.match(l):
            if l: INVALID.add(l)
            continue
        (ds.dom if exact else ds.suf).add(l)
    return ds

def load_ip(path):
    ds = DS()
    for line in open(path, encoding="utf-8", errors="ignore"):
        l = line.strip()
        if not l or l.startswith("#"): continue
        try: ds.ip.append(ipaddress.ip_network(l, strict=False))
        except ValueError: pass
    return ds

PSL_ICANN = set()   # فقط پسوندهای رسمی (com, co.uk, ir, ...)
def load_psl(path):
    s = set(); icann = True
    for line in open(path, encoding="utf-8"):
        l = line.strip()
        if "BEGIN PRIVATE DOMAINS" in l: icann = False
        if not l or l.startswith("//"): continue
        l = l.lstrip("!").replace("*.", "")
        try: l = l.encode("idna").decode() if not l.isascii() else l
        except Exception: continue
        s.add(l.lower())
        if icann: PSL_ICANN.add(l.lower())
    return s

G = defaultdict(dict)      # group -> name -> DS
PSL = set()
for line in open(manifest, encoding="utf-8"):
    g, kind, name, path = line.rstrip("\n").split("\t")
    try:
        if kind == "json": G[g][name] = load_json(path)
        elif kind == "text": G[g][name] = load_text(path)
        elif kind == "ip": G[g][name] = load_ip(path)
        elif kind == "psl": PSL = load_psl(path)
    except Exception as ex:
        say(f"خطا در خواندن {name}: {ex}")

def union(group, pred=lambda n: True):
    ds = DS()
    for n, d in G.get(group, {}).items():
        if pred(n): ds.update(d)
    return ds

# ---------------- ابزار دامنه ----------------
def parents(c):
    p = c.split(".")
    return [".".join(p[i:]) for i in range(1, len(p))]
def is_ir(c): return c.rsplit(".", 1)[-1] in IRTLD

class Matcher:
    def __init__(s, ds):
        s.plain = {x for x in ds.suf if not x.startswith(".")}
        s.dotted = {x[1:] for x in ds.suf if x.startswith(".")}
        s.exact = set(ds.dom)
        s.anc = set()          # همهٔ ورودی‌ها + والدهایشان
        for e in s.plain | s.dotted | s.exact:
            s.anc.add(e); s.anc.update(parents(e))
    def covers(s, d):          # آیا d توسط این لیست match می‌شود؟
        return d in s.plain or d in s.exact or any(a in s.plain or a in s.dotted for a in parents(d))
    def overlaps(s, c):        # c زیرمجموعه یا والدِ یک ورودی است
        return s.covers(c) or c in s.anc

def reduce_ds(ds):
    """حذف ورودی‌هایی که با یک suffix والد پوشش داده شده‌اند"""
    plain = {x for x in ds.suf if not x.startswith(".")}
    dotted = {x[1:] for x in ds.suf if x.startswith(".")}
    cov = lambda c: any(a in plain or a in dotted for a in parents(c))
    ds.suf = {x for x in ds.suf if not cov(x.lstrip(".")) and not (x.startswith(".") and x[1:] in plain)}
    ds.dom = {d for d in ds.dom if d not in plain and not cov(d)}
    return ds

# ---------------- ابزار IP (محاسبات بازه‌ای، سریع) ----------------
BOGON = [ipaddress.ip_network(x) for x in (
    "0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 "
    "192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3 "
    "::/8 64:ff9b::/96 100::/64 2001:db8::/32 fc00::/7 fe80::/10 ff00::/8").split()]
def iv(nets, v):
    xs = sorted((int(n.network_address), int(n.broadcast_address)) for n in nets if n.version == v)
    out = []
    for a, b in xs:
        if out and a <= out[-1][1] + 1: out[-1][1] = max(out[-1][1], b)
        else: out.append([a, b])
    return out
def iv_sub(A, B):
    out, j = [], 0
    for a, b in A:
        cur = a
        while j < len(B) and B[j][1] < cur: j += 1
        k = j
        while k < len(B) and B[k][0] <= b:
            if B[k][0] > cur: out.append([cur, B[k][0] - 1])
            cur = max(cur, B[k][1] + 1)
            k += 1
        if cur <= b: out.append([cur, b])
    return out
def iv_and(A, B):
    out, i, j = [], 0, 0
    while i < len(A) and j < len(B):
        lo, hi = max(A[i][0], B[j][0]), min(A[i][1], B[j][1])
        if lo <= hi: out.append([lo, hi])
        if A[i][1] < B[j][1]: i += 1
        else: j += 1
    return out
def iv_size(A): return sum(b - a + 1 for a, b in A)
def iv_nets(A, v):
    C = ipaddress.IPv4Address if v == 4 else ipaddress.IPv6Address
    res = []
    for a, b in A: res += list(ipaddress.summarize_address_range(C(a), C(b)))
    return res
def iv_has(A, starts, x):
    i = bisect.bisect_right(starts, x) - 1
    return i >= 0 and A[i][0] <= x <= A[i][1]

report = defaultdict(set)
def emit(path, rules):
    json.dump({"version": RS_VERSION, "rules": rules}, open(path, "w", encoding="utf-8"), ensure_ascii=False)

def plain_rules(ds, nets):
    rules = []
    d = {}
    if ds.dom: d["domain"] = sorted(ds.dom)
    if ds.suf: d["domain_suffix"] = sorted(ds.suf)
    if ds.kw:  d["domain_keyword"] = sorted(ds.kw)
    if ds.rx:  d["domain_regex"] = sorted(ds.rx)
    if d: rules.append(d)
    if nets: rules.append({"ip_cidr": [str(n) for n in nets]})
    return rules

# ======================= BLOCK =======================
# سه سطح منبع:
#   blockir : تبلیغات/ردیاب ایرانی          → همیشه اعمال می‌شود
#   threat  : بدافزار/فیشینگ/ماینر/TIF       → اعمال می‌شود، مگر دامنهٔ اصلیِ بانک/پرداخت/دولت/بورس/بیمه
#   block   : تبلیغات عمومی (HaGeZi و …)     → دامنهٔ اصلیِ هیچ سایت ایرانی شناخته‌شده‌ای را نمی‌بندد
#             (HaGeZi مثلاً mcinext.com، mihanblog.com، sabaidea.cloud را دارد)؛ فقط زیردامنه‌ها
def build_protect(pred):
    ds = union("direct", pred)
    ex = (ds.dom | {x.lstrip(".") for x in ds.suf} | KEEP) - DENY - (PSL - KEEP)
    anc = set()
    for e in ex: anc.add(e); anc.update(parents(e))
    return ex, anc
PROT_ALL, PROT_ALL_ANC = build_protect(lambda n: re.search(r"category(-.+)?-ir(\.srs)?$", n) and "ads" not in n)
PROT_CRIT, PROT_CRIT_ANC = build_protect(lambda n: CRIT_RE.search(n))

blk = DS()
R_PSL, R_PROT, R_THREAT = "block: پسوند عمومی (رد شد)", "block: محافظت‌شده (مسدود نشد)", "block: تهدید — با وجود ایرانی بودن مسدود شد"
for grp, ex, anc in (("blockir", set(), set()), ("threat", PROT_CRIT, PROT_CRIT_ANC), ("block", PROT_ALL, PROT_ALL_ANC)):
    src = union(grp)
    for x in src.suf:
        c = x.lstrip(".")
        # مسدود کردن یک پسوند رسمی (مثل com یا ir یا co.ir) یعنی بستن کل اینترنت → رد
        # (زون‌های DynDNS بخش خصوصی PSL عمداً در HaGeZi TIF هستند و می‌مانند)
        if c in PSL_ICANN or "." not in c:
            report[R_PSL].add(c); continue
        if is_never(c):
            report["block: ضروری (مسدود نشد)"].add(c); continue
        if c in KEEP or c in anc:
            report[R_PROT].add(c); continue
        if grp == "threat" and c in PROT_ALL_ANC: report[R_THREAT].add(c)
        blk.suf.add(x)
    for d in src.dom:
        if is_never(d):
            report["block: ضروری (مسدود نشد)"].add(d); continue
        if d in KEEP or d in ex:
            report[R_PROT].add(d); continue
        if grp == "threat" and d in PROT_ALL: report[R_THREAT].add(d)
        blk.dom.add(d)
    blk.kw |= src.kw; blk.rx |= src.rx; blk.ip += src.ip
# دامنه‌های دستی: همیشه مسدود (بدون محافظت و فیلتر)
for x in E.get("EXTRA_BLOCK", "").split():
    x = x.strip(".").lower()
    if DOMRE.match(x): blk.suf.add(x); report["block: دستی (EXTRA_BLOCK)"].add(x)
before_blk = len(blk.suf) + len(blk.dom)
reduce_ds(blk)
bogon4, bogon6 = iv(BOGON, 4), iv(BOGON, 6)
blk4 = iv_sub(iv(blk.ip, 4), bogon4); blk6 = iv_sub(iv(blk.ip, 6), bogon6)
BLK = Matcher(blk)
# گزارش فقط مواردی که واقعاً آزاد ماندند (نه آن‌هایی که لیست ایرانی مسدودشان کرد)
report[R_PROT] = {c for c in report[R_PROT] if not BLK.covers(c)}
if INVALID: report["ورودی نامعتبر در منابع (حذف شد)"] = set(INVALID)

if mode in ("all", "block"):
    nets = iv_nets(blk4, 4) + (iv_nets(blk6, 6) if WITH_V6 else [])
    blk_dom_rules, blk_ip_rules = plain_rules(blk, []), plain_rules(DS(), nets)
    if not blk_dom_rules or not blk_ip_rules:
        say("block: لیست دامنه یا IP خالی است (منابع دریافت نشدند؟) — ساخت متوقف شد")
        sys.exit(1)
    emit(os.path.join(outdir, "block-domains.json"), blk_dom_rules)
    emit(os.path.join(outdir, "block-ips.json"), blk_ip_rules)
    say(f"block: دامنه {fa(before_blk)} → {fa(len(blk.suf) + len(blk.dom))} (بعد از حذف تکراری) | "
        f"keyword {len(blk.kw)} | regex {len(blk.rx)} | IP {fa(len(nets))}")
    say(f"block: {fa(len(report[R_PROT]))} دامنهٔ ایرانی از لیست‌های عمومی محافظت شد | "
        f"{fa(len(report[R_THREAT]))} دامنهٔ ایرانی به‌خاطر تهدید مسدود ماند"
        + (f" ({', '.join(sorted(report[R_THREAT])[:5])} …)" if report[R_THREAT] else ""))
    if INVALID: say(f"block/direct: {fa(len(INVALID))} ورودی نامعتبر (IP یا کاراکتر غیرمجاز در لیست دامنه) حذف شد")

# ======================= DIRECT =======================
if mode in ("all", "direct"):
    d = union("direct")
    raw_n = len(d.suf) + len(d.dom)
    # ۱ و ۲: پسوند عمومی و دامنه‌های خارجی شناخته‌شده
    for x in list(d.suf):
        c = x.lstrip(".")
        if is_ir(c) or c in KEEP: continue
        if c in PSL:  d.suf.discard(x); report["direct: پسوند عمومی/سرویس جهانی"].add(c)
        elif c in DENY: d.suf.discard(x); report["direct: دامنهٔ خارجی شناخته‌شده"].add(c)
    for x in list(d.dom):
        if not is_ir(x) and x not in KEEP and (x in PSL or x in DENY):
            d.dom.discard(x); report["direct: دامنهٔ خارجی شناخته‌شده"].add(x)
    reduce_ds(d)
    IR = Matcher(d)

    # IP: جمع منابع − IP خصوصی − CDN/ابرهای خارجی − IP مخرب
    all4, all6 = iv(d.ip, 4), iv(d.ip, 6)
    f_ip = union("foreign").ip + STATIC_FOREIGN_IP
    f4, f6 = iv(f_ip, 4), iv(f_ip, 6)
    s0 = iv_size(all4)
    ir4 = iv_sub(iv_sub(iv_sub(all4, bogon4), f4), blk4)
    ir6 = iv_sub(iv_sub(iv_sub(all6, bogon6), f6), blk6) if WITH_V6 else []
    for n in iv_nets(iv_and(all4, f4), 4) + iv_nets(iv_and(all6, f6), 6):
        report["direct: IP متعلق به CDN/ابر خارجی"].add(str(n))
    for n in iv_nets(iv_and(all4, bogon4), 4) + iv_nets(iv_and(all6, bogon6), 6):
        report["direct: IP خصوصی/رزرو"].add(str(n))
    for n in iv_nets(iv_and(all4, blk4), 4) + iv_nets(iv_and(all6, blk6), 6):
        report["direct: IP مخرب"].add(str(n))

    # ۶ (اختیاری): بررسی DNS
    if STRICT:
        starts4, starts6 = [a for a, _ in ir4], [a for a, _ in ir6]
        cands = sorted(x for x in (IR.plain | IR.exact) if not is_ir(x) and x not in KEEP)
        say(f"strict: بررسی DNS برای {fa(len(cands))} دامنه (چند دقیقه) ...")
        socket.setdefaulttimeout(4)
        def chk(host):
            ips = set()
            try:
                for i in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP): ips.add(i[4][0])
            except Exception: return host, None
            for ip in ips:
                a = ipaddress.ip_address(ip)
                if a.version == 4 and iv_has(ir4, starts4, int(a)): return host, True
                if a.version == 6 and iv_has(ir6, starts6, int(a)): return host, True
            return host, (False if ips else None)
        with ThreadPoolExecutor(96) as ex:
            for host, res in ex.map(chk, cands):
                if res is False:
                    d.suf.discard(host); d.dom.discard(host)
                    report["direct: resolve به IP غیرایرانی (strict)"].add(host)
        IR = Matcher(d)

    # ۳ و ۵: استثنا (invert) — خارجی‌ها، sanctioned، و هم‌پوشانی با block
    inv_suf, inv_dom = set(), set()
    for name, fs in G.get("foreign", {}).items():
        tag = "direct: در لیست sanctioned" if "sanctioned" in name else "direct: سرویس خارجی (" + name.replace("geosite-", "") + ")"
        sanctioned = "sanctioned" in name
        for x in fs.suf:
            c = x.lstrip(".")
            if is_ir(c) or c in KEEP: continue
            # sanctioned: فقط اگر لیست ایران آن را پوشش دهد (آینه‌های ایرانی مثل ir.archive.ubuntu.com بمانند)
            # سرویس‌های بزرگ: هر نوع هم‌پوشانی (حتی زیردامنه‌ای از google.com در لیست ایران)
            if (IR.covers(c) if sanctioned else IR.overlaps(c)): inv_suf.add(x); report[tag].add(c)
        for x in fs.dom:
            if not is_ir(x) and x not in KEEP and IR.covers(x): inv_dom.add(x); report[tag].add(x)
    for x in blk.suf:
        c = x.lstrip(".")
        if c in KEEP: continue
        if IR.overlaps(c): inv_suf.add(x); report["direct: تبلیغات/بدافزار/فیشینگ"].add(c)
    for x in blk.dom:
        if x not in KEEP and IR.covers(x): inv_dom.add(x); report["direct: تبلیغات/بدافزار/فیشینگ"].add(x)
    tmp = DS(); tmp.suf, tmp.dom = inv_suf, inv_dom; reduce_ds(tmp)

    nets = iv_nets(ir4, 4) + iv_nets(ir6, 6)
    dom_base = plain_rules(d, [])
    if not dom_base or not nets:
        say("direct: لیست دامنه یا IP خالی است (منابع دریافت نشدند؟) — ساخت متوقف شد")
        sys.exit(1)
    neg = None
    if tmp.suf or tmp.dom:
        neg = {}
        if tmp.dom: neg["domain"] = sorted(tmp.dom)
        if tmp.suf: neg["domain_suffix"] = sorted(tmp.suf)
        neg["invert"] = True
    # استثناها (سرویس‌های خارجی/تبلیغات) روی هر دو فایل اعمال می‌شوند تا اتصال به IP ایرانی
    # که دامنهٔ sniff‌شده‌اش خارجی است (مثل google.com) direct نشود — همان رفتار نسخهٔ قبل.
    def wrap(base):
        return [{"type": "logical", "mode": "and", "rules": [base, neg]}] if neg else [base]
    emit(os.path.join(outdir, "iran-domains.json"), wrap(dom_base[0]))
    emit(os.path.join(outdir, "iran-ips.json"), wrap({"ip_cidr": [str(n) for n in nets]}))

    say(f"direct: دامنه {fa(raw_n)} → {fa(len(d.suf) + len(d.dom))} | "
        f"IPv4 {fa(len(iv_nets(ir4, 4)))} رنج | IPv6 {fa(len(iv_nets(ir6, 6)))} رنج")
    for k in sorted(report):
        if k.startswith("direct:"):
            sample = ", ".join(sorted(report[k])[:6])
            say(f"  ✂ {k[8:]}: {fa(len(report[k]))}   ({sample}{' …' if len(report[k]) > 6 else ''})")

if REPORT:
    with open(os.path.join(outdir, "report.txt"), "w", encoding="utf-8") as fh:
        for k in sorted(report):
            fh.write(f"## {k}  ({len(report[k])})\n")
            fh.write("\n".join(sorted(report[k])) + "\n\n")
PYEOF

log "۳) بررسی، پاک‌سازی و ادغام ..."
STRICT="$STRICT" REPORT="$REPORT" WITH_IPV6="$WITH_IPV6" RS_VERSION="$RS_VERSION" \
DENY_DIRECT="${DENY_DIRECT[*]}" KEEP_DIRECT="${KEEP_DIRECT[*]}" EXTRA_BLOCK="${EXTRA_BLOCK[*]}" \
NEVER_BLOCK="${NEVER_BLOCK[*]}" NEVER_BLOCK_EXACT="${NEVER_BLOCK_EXACT[*]}" \
FOREIGN_STATIC_IPS="${FOREIGN_STATIC_IPS[*]}" CRITICAL_CATEGORIES="$CRITICAL_CATEGORIES" \
  python3 "$TMP/engine.py" "$MANIFEST" "$TMP" "$MODE" || die "پردازش ناموفق بود."
[ "$STRICT" -eq 1 ] && warn "حالت strict: اگر خارج از ایران اجرا شد، ممکن است سایت‌های ایرانیِ دارای GeoDNS هم حذف شده باشند."

log "۴) کامپایل srs ..."
compile() { # compile <json> <srs>
  "$SING_BOX_BIN" rule-set compile "$1" -o "$2" >/dev/null 2>&1 \
    || "$SING_BOX_BIN" rule-set compile "$1" "$2" >/dev/null 2>&1 || die "کامپایل $2 ناموفق بود."
  is_srs "$2" || die "فایل خروجی معتبر نیست: $2"
}
test_set() { # test_set <srs> <label-yes> <label-no> <hosts...>
  local f="$1" y="$2" n="$3"; shift 3
  for t in "$@"; do
    if "$SING_BOX_BIN" rule-set match "$f" "$t" -f binary 2>&1 | grep -q 'match rules'; then
      printf '      %-22s %s\n' "$t" "$y" >&2
    else printf '      %-22s %s\n' "$t" "$n" >&2; fi
  done
}
publish() { # publish <json-name-in-TMP> <output-basename>
  compile "$TMP/$1.json" "$OUT_DIR/$2.srs"
  cp -f "$TMP/$1.json" "$OUT_DIR/$2.json"
  ok "$2.srs  ($(wc -c < "$OUT_DIR/$2.srs" | awk '{printf "%.0f KB", $1/1024}'))"
}
if [ "$MODE" != "block" ]; then
  publish iran-domains iran-all-domains
  test_set "$OUT_DIR/iran-all-domains.srs" "→ direct ✓" "→ direct نمی‌شود" \
    digikala.com shaparak.ir aparat.com snapp.ir mcinext.com \
    google.com telegram.org yektanet.com dyndns.org epizy.com
  publish iran-ips iran-all-ips
  test_set "$OUT_DIR/iran-all-ips.srs" "→ direct ✓" "→ direct نمی‌شود" \
    2.144.0.1 104.28.11.28 2001:470:1f0b::1
fi
if [ "$MODE" != "direct" ]; then
  publish block-domains ads-merged-domains
  test_set "$OUT_DIR/ads-merged-domains.srs" "→ مسدود ✓" "→ آزاد" \
    yektanet.com adivery.com googleads.g.doubleclick.net pagead2.googlesyndication.com \
    ad.doubleclick.net adservice.google.com luckyorange.com fullstory.com \
    digikala.com shaparak.ir bankmellat.ir mihanblog.com mcinext.com google.com \
    googletagmanager.com graph.instagram.com instagram.com
  publish block-ips ads-merged-ips
fi

# ----------------------- ۵) بررسی نهایی فایل‌های خروجی -----------------------
log "۵) بررسی نهایی (decompile و کنترل نوع ورودی‌ها) ..."
verify_srs() { # verify_srs <srs> <label>
  local j="$TMP/verify_$2.json"
  "$SING_BOX_BIN" rule-set decompile "$1" -o "$j" >/dev/null 2>&1 || { warn "$2: decompile ناموفق بود"; return; }
  python3 - "$j" "$2" <<'PY'
import ipaddress, json, re, sys
j, label = sys.argv[1:3]
DOMRE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$|^(ir|xn--mgba3a4f16a)$")
def L(v): return v if isinstance(v, list) else [v]
bad_dom, bad_ip, nd, ni = [], [], 0, 0
def walk(r):
    global nd, ni
    if r.get("type") == "logical":
        for x in r["rules"]: walk(x)
        return
    for k in ("domain", "domain_suffix"):
        for d in L(r.get(k, [])):
            nd += 1
            c = d.lstrip(".")
            try: ipaddress.ip_address(c); bad_dom.append(d + " (IP)"); continue
            except ValueError: pass
            if not DOMRE.match(c): bad_dom.append(d)
    for x in L(r.get("ip_cidr", [])):
        ni += 1
        try: ipaddress.ip_network(x, strict=False)
        except ValueError: bad_ip.append(x)
for r in json.load(open(j, encoding="utf-8"))["rules"]: walk(r)
print(f"    {label}: {nd:,} دامنه، {ni:,} رنج IP", file=sys.stderr)
if bad_dom: print(f"    [!] {label}: {len(bad_dom)} ورودی غیردامنه در بخش دامنه: {bad_dom[:5]}", file=sys.stderr)
if bad_ip:  print(f"    [!] {label}: {len(bad_ip)} ورودی غیر-IP در بخش ip_cidr: {bad_ip[:5]}", file=sys.stderr)
sys.exit(1 if (bad_dom or bad_ip) else 0)
PY
}
VERIFY_FAIL=0
if [ "$MODE" != "block" ]; then
  verify_srs "$OUT_DIR/iran-all-domains.srs" iran-domains || VERIFY_FAIL=1
  verify_srs "$OUT_DIR/iran-all-ips.srs"     iran-ips     || VERIFY_FAIL=1
fi
if [ "$MODE" != "direct" ]; then
  verify_srs "$OUT_DIR/ads-merged-domains.srs" ads-domains || VERIFY_FAIL=1
  verify_srs "$OUT_DIR/ads-merged-ips.srs"     ads-ips     || VERIFY_FAIL=1
fi
[ "$VERIFY_FAIL" -eq 0 ] && ok "همهٔ ورودی‌ها در جای درست هستند (دامنه در بخش دامنه، IP در بخش ip_cidr)" \
                         || warn "بررسی نهایی ایراد پیدا کرد؛ گزارش بالا را ببینید."
[ "$REPORT" -eq 1 ] && cp "$TMP/report.txt" "$OUT_DIR/report.txt" && ok "گزارش: $OUT_DIR/report.txt"

cat >&2 <<'EOF'

  ─── در کانفیگ sing-box (ترتیب مهم است: اول ads، بعد iran) ───
  "route": {
    "rule_set": [
      { "tag": "ads-merged-domains", "type": "local", "format": "binary", "path": "ads-merged-domains.srs" },
      { "tag": "ads-merged-ips",     "type": "local", "format": "binary", "path": "ads-merged-ips.srs" },
      { "tag": "iran-all-domains",   "type": "local", "format": "binary", "path": "iran-all-domains.srs" },
      { "tag": "iran-all-ips",       "type": "local", "format": "binary", "path": "iran-all-ips.srs" }
    ],
    "rules": [
      { "action": "sniff" },
      { "rule_set": ["ads-merged-domains", "ads-merged-ips"], "action": "reject" },
      { "rule_set": ["iran-all-domains", "iran-all-ips"], "outbound": "direct" }
    ],
    "final": "proxy"
  }
EOF
