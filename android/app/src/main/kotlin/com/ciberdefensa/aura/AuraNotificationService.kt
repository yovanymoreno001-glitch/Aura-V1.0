package com.ciberdefensa.aura

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicInteger

class AuraNotificationService : Service() {
    override fun onCreate() {
        super.onCreate()
        createNotificationChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createNotificationChannels(this)
        startForeground(FOREGROUND_NOTIFICATION_ID, createOngoingNotification(this))
        if (intent?.action == ACTION_ALERT) {
            postOperatorAlert(
                this,
                intent.getStringExtra(EXTRA_TITLE).orEmpty(),
                intent.getStringExtra(EXTRA_BODY).orEmpty(),
            )
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createOngoingNotification(context: Context): Notification =
        NotificationCompat.Builder(context, STATUS_CHANNEL_ID)
            .setContentTitle("Aura Mobile Defens")
            .setContentText("Servicio de alertas foreground activo.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

    companion object {
        private const val STATUS_CHANNEL_ID = "aura_protection_status"
        private const val ALERT_CHANNEL_ID = "aura_firewall_alerts"
        private const val ACTION_ALERT = "com.ciberdefensa.aura.NOTIFY_OPERATOR"
        private const val EXTRA_TITLE = "title"
        private const val EXTRA_BODY = "body"
        private const val FOREGROUND_NOTIFICATION_ID = 1019
        private const val FIRST_ALERT_NOTIFICATION_ID = 1020
        private val nextAlertNotificationId = AtomicInteger(FIRST_ALERT_NOTIFICATION_ID)
        private val validDomain = Regex(
            "(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" +
                "(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",
        )

        @JvmStatic
        fun triggerPersistentAlert(context: Context, title: String, body: String): Boolean {
            if (title.isBlank() || body.isBlank() || title.length > 120 || body.length > 2000) {
                return false
            }
            val appContext = context.applicationContext
            if (!NotificationManagerCompat.from(appContext).areNotificationsEnabled()) {
                Log.w("AuraFirewall", "Operator alert not posted: notifications are disabled.")
                return false
            }
            return try {
                val intent = Intent(appContext, AuraNotificationService::class.java)
                    .setAction(ACTION_ALERT)
                    .putExtra(EXTRA_TITLE, title)
                    .putExtra(EXTRA_BODY, body)
                ContextCompat.startForegroundService(appContext, intent)
                true
            } catch (exception: Exception) {
                Log.e("AuraFirewall", "Could not start the alert foreground service.", exception)
                false
            }
        }

        private fun postOperatorAlert(context: Context, title: String, body: String) {
            if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return
            try {
                val notification = NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                    .setContentTitle(title)
                    .setContentText(body)
                    .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setAutoCancel(true)
                    .build()
                NotificationManagerCompat.from(context).notify(
                    nextAlertNotificationId.getAndUpdate { current ->
                        if (current >= Int.MAX_VALUE) FIRST_ALERT_NOTIFICATION_ID else current + 1
                    },
                    notification,
                )
            } catch (exception: SecurityException) {
                Log.e("AuraFirewall", "Could not post operator alert.", exception)
            }
        }

        @JvmStatic
        fun triggerDgaAlert(context: Context, domain: String) {
            if (domain.length > 253 || !validDomain.matches(domain)) {
                Log.e("AuraFirewall", "Rejected an invalid blocked TLS host.")
                return
            }

            val appContext = context.applicationContext
            try {
                createNotificationChannels(appContext)
                if (!NotificationManagerCompat.from(appContext).areNotificationsEnabled()) {
                    Log.w(
                        "AuraFirewall",
                        "Blocked TLS host $domain; notifications are disabled by the user.",
                    )
                    return
                }

                val notification = NotificationCompat.Builder(appContext, ALERT_CHANNEL_ID)
                    .setContentTitle("Aura: conexión cifrada bloqueada")
                    .setContentText("Tráfico TLS a $domain detenido por el cortafuegos.")
                    .setStyle(
                        NotificationCompat.BigTextStyle()
                            .bigText("Aura detuvo un intento de evasión cifrada hacia $domain."),
                    )
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setAutoCancel(true)
                    .build()
                NotificationManagerCompat.from(appContext).notify(
                    nextAlertNotificationId.getAndUpdate { current ->
                        if (current >= Int.MAX_VALUE) FIRST_ALERT_NOTIFICATION_ID else current + 1
                    },
                    notification,
                )
            } catch (exception: SecurityException) {
                Log.e("AuraFirewall", "Could not post blocked-host alert for $domain.", exception)
            } catch (exception: IllegalArgumentException) {
                Log.e("AuraFirewall", "Could not construct blocked-host alert for $domain.", exception)
            } catch (exception: IllegalStateException) {
                Log.e("AuraFirewall", "Could not initialize blocked-host alert for $domain.", exception)
            }
        }

        private fun createNotificationChannels(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

            val manager = context.getSystemService(NotificationManager::class.java)
                ?: error("Android NotificationManager is unavailable.")
            if (manager.getNotificationChannel(STATUS_CHANNEL_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        STATUS_CHANNEL_ID,
                        "Estado de protección Aura",
                        NotificationManager.IMPORTANCE_LOW,
                    ).apply {
                        description = "Estado persistente del túnel VPN de Aura."
                    },
                )
            }
            if (manager.getNotificationChannel(ALERT_CHANNEL_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        ALERT_CHANNEL_ID,
                        "Alertas del cortafuegos Aura",
                        NotificationManager.IMPORTANCE_HIGH,
                    ).apply {
                        description = "Alertas inmediatas por conexiones cifradas bloqueadas."
                        enableLights(true)
                        enableVibration(true)
                    },
                )
            }
        }
    }
}
