# اینباندهای بهینه برای ایرانسل (پنل سنایی / 3x-ui)

کانفیگ‌های فعلی روی همه‌ی اپراتورها خوب کار می‌کنند ولی روی **ایرانسل** throttle
می‌شوند. اسکریپت `irancell_inbounds.py` چند اینباند جدید با زاویه‌های مختلف
می‌سازد که روی ایرانسل بهتر جواب می‌دهند، آن‌ها را به صورت فایل JSON آماده‌ی
ایمپورت در `./inbounds/` ذخیره می‌کند، برای هرکدام لینک اشتراک می‌سازد و در صورت
داشتن دسترسی پنل، مستقیم به پنل 3x-ui اضافه می‌کند.

## چرا ایرانسل فرق دارد؟

- TLS روی TCP پورت ۴۴۳ بعد از مقداری مصرف، شدید throttle می‌شود.
- ترافیک UDP که هدر obfuscation «whitelist‌شده» دارد (srtp/تماس تصویری،
  wireguard، dtls، wechat-video) در QoS ایرانسل اولویت می‌گیرد → اینباند mKCP با
  این هدرها معمولاً سرعت خیلی بهتری می‌گیرد.
- ترانسپورت‌های مالتی‌پلکس/چانک‌شده (gRPC و XHTTP) از DPI ایرانسل بهتر رد می‌شوند
  تا WebSocket ساده.
- Reality نیاز به دامنه/گواهی روی سرور ندارد و در برابر بلاک بر اساس SNI مقاوم
  است؛ به شرطی که SNI قرض‌گرفته‌شده خودش throttle نشده باشد.

## اینباندهای ساخته‌شده

| Remark | پورت | پروتکل/ترانسپورت | منطق ایرانسل |
|---|---|---|---|
| IR-Reality-Vision-TCP | 443 | VLESS + Reality + Vision | خط پایه |
| IR-Reality-gRPC | 8443 | VLESS + Reality + gRPC | مالتی‌پلکس، عبور بهتر از DPI |
| IR-Reality-XHTTP | 2087 | VLESS + Reality + XHTTP | جدیدترین ترانسپورت، قوی روی موبایل |
| IR-mKCP-VMess-srtp | 2095 | VMess + mKCP (هدر srtp) | سوار شدن روی QoS تماس تصویری ایرانسل |
| IR-mKCP-VLESS-wireguard | 2096 | VLESS + mKCP (هدر wireguard) | پروفایل دوم UDP whitelist |
| IR-Shadowsocks-2022 | 8388 | Shadowsocks-2022 (TCP+UDP) | فالبک سبک و کم‌سربار |

## نحوه‌ی استفاده

تنظیمات را از طریق متغیرهای محیطی بده (فایل را ویرایش نکن):

```bash
export XUI_SERVER_ADDRESS="آی‌پی یا دامنه‌ی سرور Xray"   # نه میکروتیک
export XUI_REALITY_SNI="www.datadoghq.com"              # یک SNI پرترافیک که ایرانسل throttle نکند

python3 irancell_inbounds.py        # فقط ساخت فایل JSON + لینک
```

### اضافه‌کردن مستقیم به پنل (اختیاری)

```bash
export XUI_PANEL_URL="http://آی‌پی:2053"
export XUI_PANEL_USERNAME="admin"
export XUI_PANEL_PASSWORD="..."
export XUI_PANEL_BASE_PATH=""        # اگر پنل مسیر مخفی دارد

python3 irancell_inbounds.py --push
```

اگر `--push` نزنی، فایل‌های `./inbounds/*.json` را می‌توانی دستی از منوی
Inbounds → افزودن → Import در 3x-ui وارد کنی.

## نکات تست و تیونینگ

- چند **SNI** مختلف را برای Reality امتحان کن (مثل `www.datadoghq.com`,
  `dl.google.com`, `www.speedtest.net`). بهترین SNI روی ایرانسل ممکن است با
  اپراتورهای دیگر فرق کند.
- روی یک سیم‌کارت ایرانسل واقعی A/B تست کن؛ معمولاً **mKCP-srtp** و **gRPC**
  بیشترین تفاوت سرعت را نشان می‌دهند.
- پورت‌ها را در `BUILDERS` داخل اسکریپت می‌توانی عوض کنی؛ مطمئن شو فایروال سرور
  این پورت‌ها (TCP و برای mKCP حتماً **UDP**) را باز کرده.
- فایل‌های تولیدشده شامل **کلید خصوصی و پسورد** هستند و در `.gitignore` قرار
  دارند؛ آن‌ها را کامیت نکن.
