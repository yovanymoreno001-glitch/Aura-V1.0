# Aura Mobile Defens

**Versión de la app:** `1.0.0+1` · **Modelo publicado:** `3.0.0` · **Estado:** en desarrollo (sin release pública distribuida)

Aura Mobile Defens es una aplicación Android de ciberdefensa local construida con Flutter/Dart y componentes nativos Kotlin, JNI y C. El núcleo es un `VpnService` local, sin root, que encamina el tráfico del dispositivo por una interfaz TUN procesada con [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel) más un filtro DNS y SNI propio. Los eventos de red llegan a Dart, donde un bosque aleatorio léxico local puntúa los dominios.

> Aura no es un producto certificado. No sustituye a un antivirus con motor de firmas ni a una solución MTD empresarial. La cobertura depende del dispositivo, de los permisos concedidos y de los protocolos observables (ver "Limitaciones conocidas").

![Android CI](https://img.shields.io/github/actions/workflow/status/yovanymoreno001-glitch/Aura-V1.0/android-ci.yml?branch=main&label=android%20ci)
![Modelo](https://img.shields.io/badge/modelo-3.0.0-blue)

---

## 1. Arquitectura

```text
┌──────────────────────────────── Android (Kotlin / C) ───────────────────────────────┐
│ MainActivity ── consentimiento VpnService ──► AuraVpnService (foreground, TUN)      │
│                                                   │ rutas 0.0.0.0/0 y ::/0          │
│                                                   ▼                                  │
│                          libhev-socks5-tunnel.so (lwIP en userspace)                 │
│              ┌──────────────────────┬──────────────────────┬────────────────────┐    │
│              │ hev-mapped-dns.c     │ aura_sni_firewall.c  │ filtro DNS cifrado │    │
│              │ bloqueo + alerta DGA │ ClientHello TLS/SNI  │ 853 y 443→DoH IPs  │    │
│              └──────────┬───────────┴──────────┬───────────┴────────────────────┘    │
│                         └── hev_jni_report_dns_event ──► AuraNetworkStream (UID→app) │
└───────────────────────────────────────────────────────┬──────────────────────────────┘
                              EventChannel com.aura.cyberdefense/network_stream
┌───────────────────────────────────────────────────────▼──────── Flutter / Dart ───────┐
│ SplashScreen (biometría) → AuraNetworkAuditor.ensureStarted() → AuraStateProvider (UI) │
│                                   │ BLOCKED / DGA_ALERT                                │
│                                   ▼                                                    │
│      AuraAIBrain ──► AuraAIInference (Isolate) ──► bosque JSON firmado (6 features)    │
│                                   │ amenaza confirmada                                 │
│                                   ▼                                                    │
│      addDnsBlockRule (MethodChannel) ──► reglas nativas DNS + SNI                      │
│ AgentController ◄─ AuraIntentParser (órdenes en español) ─► AuraTools / SecurityEngine │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Flujo de un evento de red

1. `hev-mapped-dns.c` intercepta las consultas DNS del túnel. Si el nombre está en la lista nativa o coincide con la heurística DGA (etiquetas de 40+ caracteres, proporción de dígitos y diversidad de caracteres), responde con bloqueo y emite el evento `1` (bloqueado) o `2` (alerta DGA).
2. `aura_sni_firewall.c` inspecciona el primer vuelo TLS en TCP/443 y TCP/853. Reensambla el ClientHello aunque llegue en varios segmentos TCP o en varios registros TLS, y bloquea por SNI (evento `3`). Si detecta la extensión ECH (`0xfe0d`), emite `4` (`ECH_OBSERVED`) con el SNI externo.
3. `AuraNetworkStream` resuelve la app de origen por UID (`ConnectivityManager.getConnectionOwnerUid`, en Android 10+) y publica el evento en el `EventChannel`.
4. Tras la autenticación biométrica, `SplashScreen` arranca `AuraNetworkAuditor` (una instancia por proceso). El auditor reenvía los eventos a `AuraStateProvider` y manda los `BLOCKED`/`DGA_ALERT` al bosque. Si el modelo confirma la amenaza, solicita una regla DNS nativa.

| Componente | Archivo | Responsabilidad |
|---|---|---|
| `MainActivity` | `android/.../MainActivity.kt` | Canales `engine`, `panic`, `biometrics`, `notifications`, `network_stream`; consentimiento VPN; verificación de firma del APK. |
| `AuraVpnService` | `AuraVpnService.kt` | Servicio VPN foreground (`specialUse`), interfaz TUN y arranque del túnel nativo. |
| `AuraNetworkStream` | `AuraNetworkStream.kt` | Cola de eventos nativos, atribución por UID y notificación al operador. |
| `AuraHostileEnvironment` | `AuraHostileEnvironment.kt` | Heurísticas de root, emulador e instrumentación. |
| `AuraAppGenomeScanner` | `AuraAppGenomeScanner.kt` | Inventario de apps con servicios sensibles activos (accesibilidad, listener de notificaciones, administración del dispositivo). |
| `AuraCryptoSecure` | `AuraCryptoSecure.kt` + `cpp/aura_crypto_secure.c` | Descifrado AES-CBC del modelo en JNI con borrado de claves. |
| `AuraNetworkAuditor` | `lib/network_auditor.dart` | Suscripción única al `EventChannel`, bitácora acotada y puente a la UI y al modelo. |
| `AuraAIBrain` | `lib/ai_brain.dart` | Carga, verificación y caché del modelo; reglas seguras. |
| `AuraAIInference` | `lib/models/aura_ai_brain.dart` | Extracción de 6 características y evaluación del bosque JSON en `Isolate`. |
| `AuraBinaryInference` | `lib/inference/aura_binary_inference.dart` | Evaluador alternativo para un formato binario de bosque. Hoy solo se usa en tests. |
| `AgentController` | `lib/agent/agent_controller.dart` | Orquesta las órdenes de consola y voz, las respuestas y las herramientas. |
| `AuraIntentParser` | `lib/agent/aura_intent_parser.dart` | Clasificación de intenciones en lenguaje natural. |
| `AuraCommandExecutor` | `lib/agent/aura_command_executor.dart` | Fachada de la UI: ejecuta una orden y mapea el evento resultante. |
| `AuraSecurityEngine` | `lib/security_engine.dart` | Integra las sondas nativas de integridad. Se invoca con "revisa mi seguridad". |

### Pilares de defensa (estado real)

| Pilar | Implementado | Limitaciones |
|---|---|---|
| 1. Entorno hostil | Heurísticas nativas (root, `su`, emulador, depurador, Frida, ADB) y verificación de la firma del APK contra `AURA_ALLOWED_CERT_SHA256`. | Heurísticas locales evadibles (Zygisk, DenyList, hooks). Falta atestación remota con Play Integrity. |
| 2. Inventario de apps | Apps con servicios de accesibilidad, listener de notificaciones o administración del dispositivo activos. | Usa `QUERY_ALL_PACKAGES`, un permiso restringido en Google Play. No hay escaneo de APK por firmas o hashes. |
| 3. Clasificación ML | Bosque aleatorio de 500 árboles con 6 características léxicas, firmado con RSA-2048 y SHA-256. | Votos sin calibrar. FPR en test de 10,7 % (ver sección 3), así que no debe usarse como bloqueo único. |
| 4. Red | DNS con bloqueo y alerta DGA; SNI TLS con reensamblado; bloqueo de DoT (853) y de DoH a IPs conocidas; detección de ECH; IPv4 e IPv6. | QUIC/HTTP3 no se inspecciona. ECH oculta el SNI real. Los resolutores DoH fuera de la lista no se detectan. |
| 5. Cadena de suministro | Firma de release verificada en CI (`release-signing-integrity.yml`), modelo firmado y publicado en Pages. | **Aún no hay** SBOM ni provenance SLSA. Las Actions no están fijadas por SHA. |

---

## 2. Filtro TLS/SNI nativo

`aura_sni_firewall.c` expone:

```c
AuraTlsSniResult aura_inspect_tls_sni (const uint8_t *payload, uint32_t len,
                                       char *sni, size_t sni_capacity);
AuraTlsSniResult aura_inspect_tls_client_hello (const uint8_t *payload,
                                                uint32_t len, char *sni,
                                                size_t sni_capacity,
                                                uint32_t *flags);
/* flags: AURA_TLS_FLAG_ECH (0x1), AURA_TLS_FLAG_NO_SNI (0x2) */
```

- **Reensamblado:** `hev-socks5-session-tcp.c` acumula los segmentos TCP en `tls_inspection_buffer` (hasta 65 560 bytes) mientras el resultado sea `INCOMPLETE`. Así cubre los ClientHello post-cuánticos (`X25519MLKEM768`), que superan un MSS.
- **Fragmentación TLS:** el ClientHello puede repartirse en varios registros de tipo `0x16`, incluso con la cabecera de handshake partida.
- **Validación:** se rechazan (`MALFORMED`) las longitudes inconsistentes, un segundo `server_name` (RFC 6066) y los nombres que no cumplen LDH. Un `MALFORMED` en el primer vuelo bloquea la conexión (fail-closed).
- **Reglas:** coincidencia exacta o por sufijo con límite de etiqueta (`evil.example` bloquea `c2.evil.example`, pero no `notevil.example`). La allowlist dinámica tiene prioridad sobre las reglas integradas de resolutores DoH (`dns.google`, `cloudflare-dns.com`, etc.).
- **Tests:** `test/native/test_aura_sni_firewall.c` cubre PQ ClientHello por segmentos, registros de 2 bytes, ECH, ausencia de SNI, reglas, allowlist, entradas malformadas y 20 000 mutaciones aleatorias, bajo AddressSanitizer y UBSan.

```sh
cc -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -fsanitize=address,undefined \
   -I android/app/src/main/cpp android/app/src/main/cpp/aura_sni_firewall.c \
   test/native/test_aura_sni_firewall.c -o /tmp/aura_sni_test -lpthread && /tmp/aura_sni_test
```

---

## 3. Modelo (Brain v2, `3.0.0`)

Asset: [`assets/model/aura_brain_model.json`](assets/model/aura_brain_model.json), con su `.sha256` y su firma `.sig` (RSA-2048, PKCS#1 v1.5, SHA-256).

| Propiedad | Valor |
|---|---:|
| Tipo | `random_forest`, clases `safe` / `threat` |
| Características | `length`, `shannon_entropy`, `digit_ratio`, `vowel_ratio`, `consonant_sequence_ratio`, `suspicious_tld` |
| Árboles / profundidad / `min_samples_leaf` | 500 / 10 / 2048 |
| Muestras de entrenamiento | 339 279 |
| Tamaño | 3 004 068 bytes |

Métricas del preset móvil sobre el holdout (para la clase `threat`). Matriz `[[13381, 1606], [13916, 43800]]` (filas reales, columnas predichas `[safe, threat]`):

| Accuracy | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|
| 0.7865 | 0.9646 | 0.7589 | 0.8495 | 0.1072 |

**Advertencia de interpretación:** el test tiene un 79 % de amenazas, por lo que la *precision* está inflada. Con una prevalencia realista del 0,1 % en el tráfico de un teléfono, la precision esperada es de alrededor de 0,7 %. Por eso el modelo debe usarse como señal secundaria y no como bloqueo único.

La orden `actualizar` descarga el JSON, el `.sha256` y la `.sig` desde <https://yovanymoreno001-glitch.github.io/Aura-V1.0/model/>, valida la firma y el digest, y solo entonces cifra e instala el modelo. Si la validación falla, la app pasa a reglas conservadoras.

### Pipeline de datos

- Amenazas: [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (MIT). Seguros: [Majestic Million](https://majestic.com/reports/majestic-million) (CC BY 3.0).
- `tool/dataset/build_dataset.py` normaliza (IDNA, sin IPs), deduplica, excluye conflictos y crea splits estratificados con semilla 42.
- Reproducción:

```sh
python -m pip install -r tool/requirements-train.txt
python tool/dataset/build_dataset.py --sources phishing_database
python tool/train_max_aura_brain.py --preset mobile
python tool/bench_aura_brain.py
python -m pytest tool/test_aura_brain.py -q
```

---

## 4. Build

Requisitos: Flutter stable, JDK 17, Android SDK Platform 36, Build-Tools 36 y el NDK que fija Flutter (`flutter.ndkVersion`; r28 con Flutter 3.47). Las librerías nativas se enlazan con `max-page-size=16384`, compatible con dispositivos de páginas de 16 KB.

ABIs: `armeabi-v7a`, `arm64-v8a` y `x86_64`. (`x86` de 32 bits se retiró porque Flutter ya no publica motor para esa ABI.)

```sh
flutter pub get
flutter analyze
flutter test
flutter build apk --debug          # instalable, firmado con la clave debug local
```

### Release firmada

`android/app/build.gradle` exige las cuatro variables de firma para cualquier tarea release y falla si faltan:

| Variable | Descripción |
|---|---|
| `AURA_KEYSTORE_PATH` | Ruta al `.jks`. Alternativa: `AURA_KEYSTORE_BASE64`, que `tool/compile_aura.sh` decodifica ignorando espacios y saltos de línea. |
| `AURA_STORE_PASSWORD` / `AURA_KEY_ALIAS` / `AURA_KEY_PASSWORD` | Credenciales del keystore. |
| `AURA_EXTRA_ALLOWED_CERT_SHA256` | Opcional. Lista de SHA-256 adicionales separados por comas que acepta la verificación de firma en runtime. **Obligatoria si se publica con Play App Signing**: añade aquí el certificado de firma de la app que muestra Play Console, porque Google vuelve a firmar los APK instalados. |
| `AURA_PUBLIC_KEY_ENV` | Clave pública RSA (DER en Base64) que verifica el modelo. |

```sh
bash tool/compile_aura.sh --check-signing
bash tool/compile_aura.sh                 # APK; AURA_BUILD_FORMAT=aab para AAB
bash tool/compile_aura.sh --verify-artifact
```

`compile_aura.sh` rechaza el certificado público `Android Debug`. Para generar el secreto de GitHub sin saltos de línea:

```sh
base64 -w0 aura-release.jks | gh secret set AURA_KEYSTORE_BASE64
```

---

## 5. CI

| Workflow | Qué hace | Secretos |
|---|---|---|
| `android-ci.yml` | Tests del parser SNI (ASan/UBSan), `flutter analyze`, `flutter test --coverage` y APK debug publicado como artefacto `aura-debug-apk`. | No |
| `android-release.yml` | APK release firmado mediante `tool/compile_aura.sh`, artefacto `Aura-Release-APK`. | Sí |
| `release-signing-integrity.yml` | Comprueba que release nunca use la firma debug y que el firmado con una clave efímera funcione. | No |
| `model-training.yml` | Dataset, entrenamiento, benchmark y tests del modelo. | No |
| `deploy-model-pages.yml` | Publica el modelo, el SHA-256 y la firma en GitHub Pages. | No |

`codemagic.yaml` define el pipeline `android-build` equivalente con el grupo `production_keys`.

---

## 6. Estructura

```text
android/app/src/main/
  kotlin/com/ciberdefensa/aura/   MainActivity, AuraVpnService, AuraNetworkStream,
                                  AuraHostileEnvironment, AuraAppGenomeScanner,
                                  AuraCryptoSecure, AuraNotificationService, AuraUpdateWorker
  java/hev/htproxy/               TProxyService (puente JNI de hev)
  cpp/                            aura_sni_firewall.{c,h}, aura_crypto_secure.c,
                                  hev-socks5-tunnel/ (terceros, con parches Aura)
lib/
  agent/          agent_controller, agent_event, aura_intent_parser,
                  aura_command_executor, aura_tools, aura_whitelist
  crypto/         aura_crypto_layer
  inference/      aura_binary_inference
  infrastructure/security/aura_dynamic_whitelist
  models/         aura_ai_brain (AuraAIInference)
  providers/      aura_state_provider
  screens/        splash_screen, aura_core_screen
  ai_brain, network_auditor, security_engine, secure_vault, secure_memory,
  voice_engine, radar_waves, main
test/             tests Dart + native/test_aura_sni_firewall.c
tool/             dataset, entrenamiento, benchmark, firma y build
```

Los nombres de los canales Flutter (`com.aura.cyberdefense/*`) son identificadores de canal, no paquetes Java. El paquete de la aplicación y de todo el código Kotlin es `com.ciberdefensa.aura`.

---

## 7. Limitaciones conocidas

- **QUIC/HTTP3:** no se inspecciona. Los Initial de QUIC son descifrables (RFC 9001), así que es una mejora posible.
- **ECH:** cuando el cliente usa ECH, solo se ve el SNI externo; Aura lo reporta como `ECH_OBSERVED`. Mitigación pendiente: responder NODATA a las consultas DNS de tipo HTTPS (RR 65) en el resolver del túnel.
- **Biometría obligatoria:** la consola exige biometría `BIOMETRIC_STRONG`; sin ella, la app no abre la consola.
- **Ranura VPN única:** mientras Aura está activa no puede usarse otra VPN.
- **Política de Google Play:** publicar requiere la declaración de `VpnService` (categoría de seguridad del dispositivo), divulgación destacada, política de privacidad y justificación de `QUERY_ALL_PACKAGES`.
- **Cobertura:** `android-ci.yml` publica el porcentaje de cobertura de líneas Dart. No hay benchmark en dispositivos reales.

## 8. Roadmap

1. Atestación con Play Integrity verificada en servidor (sustituir las heurísticas locales como decisión principal).
2. Calibración del modelo y umbral por FPR ≤ 0,1 %; splits por eTLD+1 y temporales; características de edad de dominio y CT.
3. Extracción de SNI en QUIC Initial y modo estricto anti-ECH.
4. Manifiesto firmado con versión monotónica (anti-rollback) para el modelo y las listas.
5. SBOM CycloneDX y provenance SLSA en `android-release.yml`.
6. Escáner de APK por hash y certificado frente a reputación.

## 9. Licencias

- Código Aura: licencia propietaria ([`LICENSE`](LICENSE)).
- `hev-socks5-tunnel`: MIT, © 2022 hev.
- Phishing.Database: MIT. Majestic Million: CC BY 3.0.
