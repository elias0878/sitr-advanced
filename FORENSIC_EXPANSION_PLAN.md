# خطة سِتر الاحترافية للتوسعة الجنائية العميقة

> **الهدف:** رفع نطاق الاسترجاع والتحليل الحقيقي، مع فصل ثلاث طبقات لا يجوز خلطها: **أثر مستخرج**، **دليل بنيوي/توقيع**، و**مؤشر إحصائي**. لا تتضمن الخطة كسر كلمات المرور أو تنفيذ الحمولات أو تسميـة احتمال على أنه استرداد مؤكد.

## جدول التنفيذ من 20 خطوة

| # | خطوة التنفيذ | المخرج القابل للتحقق | الحالة |
|---:|---|---|---|
| 1 | تثبيت حدود الدليل وسلامة التشغيل | لا تنفيذ للحمولات، لا تخمين مفاتيح، وحدود حجم/ذاكرة | مكتمل |
| 2 | تثبيت هوية الملف | SHA-256، حجم، magic، entropy، ومسح متدفق للملف كاملاً | مكتمل |
| 3 | خريطة بنية الحاوية | PNG/JPEG/WebP/GIF/BMP/TIFF مع tail والأقسام الخاصة | مكتمل |
| 4 | توسيع metadata | EXIF/GPS/IPTC/XMP/ICC/MakerNote/thumbnail وحقول الحاوية | مكتمل |
| 5 | تفكيك provenance | مؤشرات APP11/JUMBF/caBX/C2PA وحالة تحقق منفصلة | مكتمل |
| 6 | فحص الـ EOF والـ polyglot والـ slack | tail، التوقيعات الداخلية، الحشو والـ chunks الخاصة | مكتمل |
| 7 | نحت الملفات المضمنة | ZIP/PDF/GZIP/صور/صوت/قواعد بيانات/ملفات تنفيذية مرشحة | مكتمل |
| 8 | استخراج محتوى آمن | أسماء ZIP، معاينات Deflate/GZIP، حقول PDF، ID3، WAVE INFO | مكتمل |
| 9 | دعم ضغط وتدفقات إضافية | معاينات zlib محدودة وآمنة في مناطق مرشحة | مكتمل |
| 10 | توسيع مسارات LSB | ترتيبات RGB/BGR/RGBA/ARGB، القنوات، planes 0–7، alignment | مكتمل |
| 11 | ترميزات النص | ASCII وUTF-8 وUTF-16 مع بصمات ملفات | مكتمل |
| 12 | مؤشرات LSB الإحصائية | χ²، entropy، توازن LSB، PVD، BPCS، ومؤشر RS-style | مكتمل |
| 13 | تحليل JPEG التحويلي | JFIF/SOF/DQT/DHT/APP/MPF/XMP الممتد وDCT coverage | مكتمل |
| 14 | ربط أدوات spatial المتخصصة | zsteg + StegExpose عند توفرهما محلياً | مكتمل |
| 15 | ربط أدوات JPEG/ML المتخصصة | stegdetect وAletheia `auto` بلا brute force | مكتمل |
| 16 | دعم adaptive/AI بطريقة صادقة | جداول تغطية HUGO/WOW/UNIWARD/MiPOD/HILL/SteganoGAN مع حدود النموذج | مكتمل |
| 17 | فحص دفاعي للحمولات | ClamAV وYARA محلياً وقواعد يتحكم بها المستخدم | مكتمل |
| 18 | تقرير أدلة موحد | JSON يضم المصدر، offset، النوع، والمستوى وحدود النتيجة | مكتمل |
| 19 | اختبار fixtures | ZIP/Deflate/PDF/ID3/WAVE/ICC/C2PA/thumbnail وموضع وسط الملف | مكتمل |
| 20 | تدقيق، commit، نشر، والتحقق من alias | syntax + runner + production HTTP/DOM checks | مكتمل |

## مصفوفة التغطية والنتيجة الصادقة

| عائلة التقنية/البيان | طبقة الويب | المشغل المحلي الاختياري | نوع النتيجة | الحد الأساسي |
|---|---|---|---|---|
| EXIF/GPS/IPTC/XMP/ICC | قراءة وتحليل محلي | ExifTool `-ee3 -api RequestAll=3` | مستخرج | قد تكون البيانات محذوفة أو مشفرة |
| C2PA/JUMBF | اكتشاف البنية والمواقع | `c2patool` عند سماح المستخدم بالشبكة | بنيوي / تحقق خارجي | لا يثبت التوقيع من مجرد marker |
| ZIP/PDF/GZIP/ID3/WAVE | أسماء وmetadata ومعاينة محتوى محدودة | `zipinfo`, `7z`, `pdfinfo`, `ffprobe` | مستخرج/بنيوي | التدفقات المشفرة أو التالفة لا تُفك بلا مفتاح |
| EOF/slack/polyglot | خريطة tail وتواقيع كاملة | `binwalk`, `file`, `strings` | بنيوي | توقيع وحده لا يثبت اكتمال الملف |
| LSB/RGB/alpha/palette | مسارات متعددة ونصوص وبصمات | `zsteg`, StegExpose | مستخرج أو إحصائي | المفاتيح/التبعثر غير المعروف قد يمنع الاسترداد |
| PVD/BPCS/RS/χ² | مقاييس محلية | StegExpose/Aletheia عند توفرهما | إحصائي | لا تمثل النتيجة احتمالاً عالمياً أو حكماً نهائياً |
| JPEG JSteg/F5/OutGuess | بنية JPEG وDCT coverage | `stegdetect`, Aletheia `auto` | إحصائي | الأدوات JPEG-only واحتمالية ومعرضة للـ false positives/negatives |
| HUGO/WOW/UNIWARD/MiPOD/HILL/STC | وصف مستوى التغطية فقط | Aletheia models/commands إن ثبتت محلياً | إحصائي | يلزم model/معايرة مناسبة، لا payload recovery عام |
| DWT/DFT/IWT/SVD/spread spectrum | مؤشرات حاوية/بكسل فقط | أداة أو نموذج المصدر | إحصائي | يلزم sync/key/algorithm |
| SteganoGAN/CNN/generative | لا ادعاء استخراج | Aletheia أو detector model صالح | إحصائي | يلزم checkpoint وبيانات معايرة متوافقة |
| payloads/malware | تصنيف magic فقط | ClamAV/YARA/OLE checks | دفاعي | magic ليس حكم malware |

## مصادر قرار التنفيذ

| المصدر | القرار الذي بُني عليه |
|---|---|
| [zsteg](https://github.com/zed-0xff/zsteg/) | توسيع bit/channel/order/prime/zlib coverage لـ PNG/BMP في المشغل المحلي؛ لا تُشغّل حمولة مجهولة تلقائياً. |
| [Aletheia](https://github.com/daniellerch/aletheia) | `auto` وSPA/RS/WS وميزات SRM/GFR/DCTR أدوات تقييم احتمالية، مع استبعاد أوامر brute-force صراحةً. |
| [StegExpose](https://github.com/b3dk7/StegExpose) | χ² وRS وSample Pairs وPrimary Sets تُعرض كمجموعة مؤشرات لا كدليل قاطع. |
| [ExifTool documentation](https://exiftool.org/exiftool_pod.html) | `-ee3 -api RequestAll=3` يوسّع قراءة الوثائق/الصور المضمنة؛ يجب ضبط timeout ومخرجات التقرير. |
| [C2PA 2.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html) | JPEG APP11 وPNG `caBX` وJUMBF هي أدلة بنيوية؛ تحقق الثقة والتوقيع وظيفة verifier. |
| [stegdetect manual](https://man.cx/stegdetect) | يقتصر على JPEG واختباراته احتمالية؛ الحساسية ليست برهاناً ولا استرداداً. |
| [Binwalk reference](https://embeddedbits.org/reverse-engineering-my-routers-firmware-with-binwalk-embeddedbits/) | نستخدم signature/entropy فقط افتراضياً؛ لا `-e` أو تشغيل أدوات استخراج تلقائي. |

## سياسة النتائج

1. **Recovered**: تم فك البنية أو النص/metadata بصورة قابلة للعرض.
2. **Carved candidate**: عُثر على بداية ملف أو stream؛ قد يكون تالِفاً أو عرضياً حتى يثبت parsing.
3. **Structural indicator**: دليل EOF أو chunk غير قياسي أو حجم متضارب.
4. **Statistical indicator**: قيمة قياس قابلة للمراجعة، وليست نسبة يقين.
5. **External-verifier result**: ناتج أداة محلية موثق باسم الأداة والإصدار والأمر والـ return code.

لا تظهر كلمة «مؤكد» إلا مع استرداد صالح أو تحقق تشفيري من أداة مختصة.
