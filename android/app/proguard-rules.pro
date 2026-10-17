-keep class com.ciberdefensa.aura.MainActivity { *; }
-keep class com.ciberdefensa.aura.AuraVpnService { *; }
-keep class hev.htproxy.TProxyService { *; }
-keep class com.ciberdefensa.aura.AuraCryptoSecure { *; }
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}