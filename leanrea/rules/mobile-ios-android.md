# Mobile Reverse Engineering Guide: iOS (IPA) & Android (APK)

This guide provides targeted instructions for analyzing mobile application packages, extracting API surfaces, data models, and native libraries.

## 1. iOS Application Analysis (`.ipa`)

An `.ipa` file is a ZIP archive containing `Payload/<AppName>.app/`.

### A. Unpacking & Binary Extraction
```sh
T=./app.ipa; X=$(mktemp -d "${TMPDIR:-/tmp}/re-ipa.XXXXXX")
unzip -q "$T" -d "$X"
APP=$(find "$X/Payload" -maxdepth 1 -name '*.app' | head -1)
echo "App Bundle: $APP"

# Extract binary name from Info.plist
if command -v plutil >/dev/null 2>&1; then
  BIN_NAME=$(plutil -extract CFBundleExecutable raw "$APP/Info.plist")
else
  BIN_NAME=$(python3 -c "import plistlib; print(plistlib.load(open('$APP/Info.plist', 'rb'))['CFBundleExecutable'])")
fi
BIN="$APP/$BIN_NAME"
file "$BIN"
```

### B. Core Data Model Archaeology (`.momd` / `.mom`)
Compiled Core Data models reside in `.momd` directories containing versioned `.mom` files.
- Each `.mom` file represents an explicit database schema version corresponding to application releases.
- Tracing entity and property changes across versions reveals product feature ship history:
```sh
# Count migration steps
find "$APP" -path '*/*.momd/*.mom' | sort
# Extract entity names from compiled models
strings "$APP"/*.momd/*.mom | rg -o '[A-Z][a-zA-Z0-9]+Entity' | sort -u
```

### C. Swift & Objective-C Reflection Metadata
```sh
# Swift classes, protocols, enums, structs
strings -a "$BIN" | rg '(class|struct|enum|protocol)\s+[A-Z][a-zA-Z0-9]+' | sort -u | head -100

# Demangle Swift symbols (on macOS or systems with swift-demangle)
if command -v swift-demangle >/dev/null 2>&1; then
  nm -gU "$BIN" 2>/dev/null | swift-demangle | rg 'type metadata accessor' | head -100
fi

# Embedded Frameworks (third-party SDKs)
ls -la "$APP/Frameworks/" 2>/dev/null
```

### D. Provisioning & Entitlements
```sh
# Read entitlements and application ID
strings "$APP/embedded.mobileprovision" | rg -A 10 '<key>Entitlements</key>' | head -40
```

---

## 2. Android Application Analysis (`.apk`)

An `.apk` file is a ZIP archive containing DEX bytecode, compiled resources, and native `.so` libraries.

### A. Decompilation with JADX
```sh
T=./app.apk; X=$(mktemp -d "${TMPDIR:-/tmp}/re-apk.XXXXXX")
jadx -d "$X/src" --show-bad-code "$T"
```

### B. REST API Endpoint Reconstruction (Retrofit)
Retrofit interfaces declare HTTP endpoints using annotations:
```sh
# List all HTTP endpoints with HTTP method and relative path
rg -n '@(GET|POST|PUT|DELETE|PATCH|HEAD)\b' "$X/src" --glob '*.java' --glob '*.kt' | sort

# Identify Base URL constants
rg -n -i 'baseUrl|BASE_URL|api_url' "$X/src" --glob '*.java' --glob '*.kt' | head -30

# Identify Retrofit service creation
rg -n 'create\(.*Service.*\.class\)' "$X/src" --glob '*.java' --glob '*.kt'
```

### C. Networking Interceptors & Auth Headers (OkHttp)
```sh
# Interceptor implementations reveal auth headers, HMAC request signing, and token refresh
rg -l 'implements Interceptor|Interceptor\s*\{' "$X/src" --glob '*.java' --glob '*.kt'
```

### D. Data Serialization Models (Gson / Moshi / Jackson / Kotlinx)
```sh
# Search JSON field mappings
rg -n '@(SerializedName|Json|JsonProperty)\b' "$X/src" --glob '*.java' --glob '*.kt' | head -100

# Kotlin Data Classes representing request/response schemas
rg -n 'data class\s+[A-Za-z0-9]+\s*\(' "$X/src" --glob '*.kt' | head -100
```

### E. Flutter & React Native Detection in APKs
- If `lib/*/libflutter.so` is present: Flutter app. Dart AOT code is in `libapp.so`.
  - Snapshot hash magic: find `f5 f5 dc dc` in `libapp.so`; the 32 hex bytes at offset +20 identify the exact Dart SDK commit.
- If `lib/*/libhermes.so` or `assets/index.android.bundle` is present: React Native with Hermes bytecode.
  - Hermes bytecode magic is `c6 1f bc 03`. Use `hermes-dec` or `hbc-decompiler`.
