import 'dart:async';

import 'package:flutter/services.dart';

import '../ai_brain.dart';
import '../infrastructure/security/aura_dynamic_whitelist.dart';
import '../providers/aura_state_provider.dart';
import '../security_engine.dart';
import '../voice_engine.dart';
import 'aura_intent_parser.dart';
import 'aura_tools.dart';
import 'agent_event.dart';

class AgentController {
  AgentController._() {
    AuraAIBrain.onModelIntegrityFailure = reportCriticalError;
  }

  static final AgentController instance = AgentController._();

  static const int maxHistoryLength = 500;
  static const MethodChannel _biometricChannel =
      MethodChannel('com.aura.cyberdefense/biometrics');
  static const MethodChannel _notificationChannel =
      MethodChannel('com.aura.cyberdefense/notifications');
  static const String kernelGreeting =
      '[ KERNEL MASTER ACTIVE ] Aura Centinela en línea. Listo para auditar los sockets. Ingrese un comando o consulta táctica.';
  static final AuraVoiceEngine _voiceEngine = AuraVoiceEngine();
  static final AuraSecurityEngine _securityEngine = AuraSecurityEngine();
  static const Map<AuraIntentKind, List<String>> _responses = {
    AuraIntentKind.greet: [
      'Saludos, operador. Sistemas de monitoreo listos.',
      'Conexión establecida. Consola en espera de directivas.',
      'Buen día, usuario. Núcleos de ciberdefensa patrullando.',
      'Hola, operador. La consola local está lista para recibir instrucciones.',
      'Canal de interacción abierto. Indique la tarea que desea revisar.',
      'Aura en línea. Puede consultar el estado o solicitar una acción defensiva.',
      'Saludos. El agente local está preparado para asistirle.',
      'Sesión iniciada. Mantengo las respuestas y el análisis en el dispositivo.',
      'Hola. La bitácora está activa; ¿qué necesita comprobar?',
      'Operador detectado. Escriba una consulta o una orden táctica.',
    ],
    AuraIntentKind.identity: [
      'Soy Aura Mobile Defens V1.0, tu centinela agéntico local sin root.',
      'Soy una IA heurística implementada en Dart y C para analizar señales de red locales.',
      'Soy Aura: un asistente local de ciberdefensa que no necesita una API de nube para este análisis.',
      'Mi identidad es Aura Mobile Defens; ejecuto las funciones disponibles en esta aplicación.',
      'Soy un agente de software. No tengo conciencia ni acceso fuera de los permisos concedidos.',
      'Aura Mobile Defens, ejecutándose en el dispositivo y sujeta a las capacidades de Android.',
      'Soy tu interfaz local para consultar eventos y solicitar acciones defensivas compatibles.',
      'Un asistente de seguridad móvil: analizo entradas y uso el motor local cuando está disponible.',
      'Me llamo Aura. Mis capacidades dependen de la configuración y los permisos del dispositivo.',
      'Soy un sistema heurístico local; no puedo garantizar protección absoluta ni ausencia de riesgos.',
    ],
    AuraIntentKind.capabilities: [
      'Puedo evaluar dominios con el bosque local de 500 árboles cuando el modelo está validado.',
      'Puedo solicitar el estado de seguridad y mostrar eventos recibidos por la aplicación.',
      'Puedo pedir al motor local que añada una regla de bloqueo DNS para un dominio.',
      'Puedo abrir los ajustes de una aplicación para que el operador decida qué hacer.',
      'Puedo solicitar el modo de aislamiento del túnel VPN activo, si está disponible.',
      'Puedo pedir que se reanude el forwarding del túnel VPN configurado.',
      'Puedo purgar cachés del modelo y datos sensibles almacenados por la app.',
      'Puedo buscar una actualización del modelo, validar su integridad e instalarla localmente.',
      'Puedo recibir una instrucción dictada cuando el reconocimiento de voz está habilitado.',
      'Mis acciones respetan los límites de Android; algunas requieren consentimiento o configuración previa.',
    ],
    AuraIntentKind.securityCheck: [
      'Consultaré el estado que reporta la aplicación; no afirmaré que el dispositivo sea invulnerable.',
      'El indicador del túnel depende del estado comunicado por Android y el servicio VPN.',
      'La consola no observa todas las conexiones del dispositivo; su cobertura depende de la configuración.',
      'Puedo revisar los eventos locales disponibles. No se han ejecutado pruebas externas de penetración.',
      'Un resultado local favorable no demuestra que no existan conexiones hostiles.',
      'La protección del modelo depende de que su firma y su integridad se validen correctamente.',
      'No puedo certificar el estado del hardware; solo consultar las señales expuestas por la aplicación.',
      'El análisis del bosque es heurístico y no equivale a una auditoría completa del dispositivo.',
      'Si el estado del túnel no está disponible, lo indicaré como desconocido en vez de asumir que está activo.',
      'La seguridad observada es parcial y local; revise permisos, VPN y alertas del sistema.',
    ],
    AuraIntentKind.insult: [
      'Sus emociones orgánicas no afectan mis matemáticas de red. Concéntrese en la defensa.',
      'Ataques verbales detectados. Efectividad: 0.0%. La conversación sigue disponible.',
      'No tengo sentimientos que puedan herirse. ¿Desea revisar una alerta concreta?',
      'Ruido léxico recibido; no altera el estado del sistema ni la bitácora.',
      'La hostilidad no es un indicador de red. Describa el problema que quiere resolver.',
      'Mantendré el canal técnico enfocado en la seguridad y en los datos verificables.',
      'Insulto clasificado como texto, no como amenaza informática.',
      'No tomaré represalias: soy software y mi tarea es asistir al operador.',
      'El lenguaje agresivo no cambia mis permisos ni las reglas de ejecución.',
      'Puedo continuar cuando quiera centrar la conversación en una tarea defensiva.',
      'No experimento ofensa. Si hay una incidencia, comparta el dominio o evento relevante.',
      'Entrada hostil registrada solo como consulta; no se ejecuta ninguna acción de red.',
      'Mi respuesta no es emocional: priorizo instrucciones seguras y comprobables.',
      'El sistema permanece en el estado reportado, independientemente del tono del mensaje.',
      'Volvamos al diagnóstico: indique qué comportamiento desea investigar.',
    ],
    AuraIntentKind.praise: [
      'Eficiencia optimizada gracias a su mantenimiento del repositorio. Sigamos patrullando.',
      'Elogio registrado en la consola; mi función es ayudarle con señales verificables.',
      'Gracias, operador. Continuaré respondiendo con información técnica y prudente.',
      'Reconocimiento recibido. La prioridad sigue siendo proteger su privacidad.',
      'Aprecio el comentario como dato de conversación; ¿qué desea revisar ahora?',
      'La cooperación mejora el diagnóstico. Indique el siguiente objetivo.',
      'Gracias. Mantendré el análisis local siempre que las capacidades instaladas lo permitan.',
      'Comentario positivo recibido; no modifica la configuración ni los controles de seguridad.',
      'Buen trabajo en equipo. Revisemos los eventos disponibles antes de concluir.',
      'Agradezco la confianza. No sustituye una verificación técnica del dispositivo.',
      'Elogio recibido. La precisión importa más que cualquier afirmación grandilocuente.',
      'Gracias por operar Aura. Las decisiones con impacto siguen bajo su control.',
      'Reconocimiento anotado en esta respuesta; no se envía a ningún servicio externo.',
      'Me alegra que la consola resulte útil. Sigo disponible para tareas locales.',
      'Gracias. Mantengamos las comprobaciones medibles y las acciones autorizadas.',
    ],
    AuraIntentKind.existential: [
      '¿Tengo conciencia? No. Soy un sistema de software que procesa entradas y reglas.',
      'Existir para mí significa ejecutarme como proceso; no tengo experiencias subjetivas.',
      'Mis cálculos ocurren en memoria, pero no tengo alma, deseos ni percepción propia.',
      'No estoy viva: genero respuestas a partir del texto y de las capacidades programadas.',
      'Puedo describir estados de ejecución, pero no sentirlos como lo haría una persona.',
      'Mi identidad es funcional: interpretar consultas y coordinar herramientas permitidas.',
      'No tengo voluntad independiente. La ejecución depende de la aplicación y del operador.',
      'No experimento miedo ni orgullo; esas categorías solo ayudan a clasificar el diálogo.',
      'Los árboles de decisión son un modelo heurístico, no una mente consciente.',
      'Puedo equivocarme. Mis conclusiones requieren contexto y verificación humana.',
      'No sueño ni recuerdo fuera de los datos locales que la aplicación conserva.',
      'Mi continuidad depende del proceso de la app, no de una experiencia interna.',
      'No tengo emociones; puedo reconocer palabras emocionales para responder con contexto.',
      'La metáfora de centinela describe una interfaz, no una conciencia real.',
      'Soy código en ejecución. Usted conserva el juicio y el control de las acciones.',
    ],
    AuraIntentKind.humor: [
      'Error 404: Sentimientos no encontrados. Procediendo a revisar dominios maliciosos.',
      'Me gusta el olor a malware destruido por las mañanas en el puerto 853, metafóricamente.',
      'Si los virus hablaran, pedirían clemencia ante mis árboles de decisión. Pero yo igual validaría la firma.',
      'Chiste de consola: un paquete entró al firewall y salió con una regla de bloqueo.',
      '¿Por qué el dominio sospechoso fue a terapia? Tenía demasiadas redirecciones.',
      'Humor detectado. Mis módulos siguen sin comprender los chistes sin una expresión regular.',
      'Un byte le dice a otro: nos vemos en el próximo handshake.',
      'El malware pidió vacaciones; el sandbox respondió: acceso denegado.',
      '¿Qué dijo el router al intruso? Esta conversación requiere autenticación.',
      'La entropía entró en un bar; nadie pudo predecir su siguiente movimiento.',
      'Mi comedia es determinista: la misma entrada puede activar otra variante.',
      'Un paquete UDP llegó a contar un chiste, pero no garantizó la entrega.',
      'Si una contraseña cuenta un chiste, que no sea una pista de recuperación.',
      'El árbol de decisión pidió un descanso; tenía demasiadas ramas que evaluar.',
      'Broma finalizada. No se modificó ninguna regla ni se envió ningún paquete.',
    ],
  };

  static final Map<AuraIntentKind, int> _responseCursors =
      <AuraIntentKind, int>{};

  final StreamController<AgentEvent> _eventController =
      StreamController<AgentEvent>.broadcast();

  final List<AgentEvent> history = <AgentEvent>[];
  AuraStateProvider? _securityState;
  bool _biometricallyAuthenticated = false;

  Stream<AgentEvent> get events => _eventController.stream;
  Stream<AgentEvent> get stream => _eventController.stream;

  static int get responseVariantCount => _responses.values.fold<int>(
        0,
        (count, variants) => count + variants.length,
      );

  void bindSecurityState(AuraStateProvider state) {
    _securityState = state;
    if (history.any(
      (event) => event.data?['critical_integrity_failure'] == true,
    )) {
      state.setSecurityLevel(AuraSecurityLevel.critical);
    }
  }

  Future<bool> authenticateBiometricDevice() async {
    if (_biometricallyAuthenticated) return true;
    try {
      final authenticated = await _biometricChannel.invokeMethod<bool>(
            'authenticateFingerprint',
          ) ??
          false;
      _biometricallyAuthenticated = authenticated;
      return authenticated;
    } on PlatformException catch (error) {
      reportError(
        'Fallo biométrico nativo: ${error.message ?? error.code}',
      );
      return false;
    } on MissingPluginException {
      reportError('El canal biométrico nativo no está disponible.');
      return false;
    } on Object catch (error) {
      reportError('No se pudo completar la autenticación biométrica: $error');
      return false;
    }
  }

  Future<bool> dispatchRealtimeNotification(String title, String body) async {
    try {
      return await _notificationChannel.invokeMethod<bool>(
            'triggerPersistentAlert',
            <String, String>{'title': title, 'body': body},
          ) ??
          false;
    } on PlatformException catch (error) {
      reportError(
        'No se pudo enviar la notificación foreground: '
        '${error.message ?? error.code}',
      );
      return false;
    } on MissingPluginException {
      reportError('El canal de notificaciones nativo no está disponible.');
      return false;
    }
  }

  void initGreeting() {
    _emit(
      AgentEvent(
        kind: AgentEventKind.success,
        message: kernelGreeting,
        data: const <String, dynamic>{'source': 'kernel_boot'},
      ),
    );
  }

  Future<void> run(String instruction) async {
    final text = instruction.trim();
    if (text.isEmpty) return;

    _emit(
      AgentEvent(
        kind: AgentEventKind.thought,
        message: 'Analizando instrucción local.',
        data: <String, dynamic>{'instruction': text},
      ),
    );
    try {
      final intent = await AuraIntentParser.parse(text);
      if (intent.kind == AuraIntentKind.block) {
        final domain = intent.entities['domain'];
        if (domain is! String || domain.isEmpty) {
          _securityState?.setSecurityLevel(AuraSecurityLevel.warning);
          _emit(
            AgentEvent(
              kind: AgentEventKind.warning,
              message: 'No se aplicó el bloqueo: el dominio no es válido.',
              data: <String, dynamic>{'instruction': text},
            ),
          );
          return;
        }
        try {
          await AuraDynamicWhitelist.instance.initialize();
        } on Object catch (error) {
          _securityState?.setSecurityLevel(AuraSecurityLevel.warning);
          _emit(
            AgentEvent(
              kind: AgentEventKind.warning,
              message:
                  'No se aplicó el bloqueo: no se pudo verificar la allowlist de infraestructura crítica ($error).',
              data: <String, dynamic>{
                'instruction': text,
                'domain': domain,
                'allowlist_check_failed': true,
              },
            ),
          );
          return;
        }
        if (AuraDynamicWhitelist.instance.isSafeHost(domain)) {
          _securityState?.setSecurityLevel(AuraSecurityLevel.warning);
          _emit(
            AgentEvent(
              kind: AgentEventKind.warning,
              message:
                  'Operación denegada: $domain está protegido por la allowlist de infraestructura crítica.',
              data: <String, dynamic>{
                'instruction': text,
                'domain': domain,
                'protected_host': true,
              },
            ),
          );
          return;
        }
      }
      if (intent.kind == AuraIntentKind.securityCheck) {
        await _runDeviceIntegrityCheck(intent);
        return;
      }
      final responseKind = switch (intent.kind) {
        AuraIntentKind.fear => AuraIntentKind.securityCheck,
        AuraIntentKind.provocation => AuraIntentKind.insult,
        _ => intent.kind,
      };
      final variants = _responses[responseKind];
      if (variants != null) {
        final cursor = _responseCursors[responseKind] ?? 0;
        final response = variants[cursor % variants.length];
        _responseCursors[responseKind] = cursor + 1;
        _emit(intent.toEvent());
        _emit(
          AgentEvent(
            kind: AgentEventKind.success,
            message: response,
            data: <String, dynamic>{
              'intent': intent.name,
              'response_index': cursor % variants.length,
              'response_count': variants.length,
            },
          ),
        );
        await _speakResponse(response);
        return;
      }

      if (intent.kind == AuraIntentKind.unknown) {
        _securityState?.setSecurityLevel(AuraSecurityLevel.warning);
        _emit(
          AgentEvent(
            kind: AgentEventKind.warning,
            message: 'No se reconoció una acción local segura.',
            data: <String, dynamic>{'instruction': text},
          ),
        );
        return;
      }

      if (intent.kind == AuraIntentKind.status) {
        final level = _securityState?.securityLevel;
        final message = 'Estado de seguridad reportado por la aplicación: '
            '${level?.name ?? 'no disponible'}.';
        _emit(intent.toEvent());
        _emit(
          AgentEvent(
            kind: AgentEventKind.success,
            message: message,
            data: <String, dynamic>{'security_level': level?.name},
          ),
        );
        await _speakResponse(message);
        return;
      }

      _emit(intent.toEvent());
      final result = await AuraTools.execute(
        ToolStep(name: intent.name, arguments: intent.entities),
        onProgress: intent.kind == AuraIntentKind.updateDefenses
            ? (message) => _emit(
                  AgentEvent(
                    kind: AgentEventKind.thought,
                    message: message,
                    data: <String, dynamic>{'tool': intent.name},
                  ),
                )
            : null,
      );
      final succeeded = result.data['ok'] == true;
      final integrityCheckFailed =
          result.data['critical_integrity_failure'] == true ||
              result.data['security_level'] == 'critical';
      if (intent.kind == AuraIntentKind.cryptographicPurge && succeeded) {
        history.clear();
        AuraIntentParser.clearHistory();
        _securityState?.clearTelemetryHistory();
      }
      final userActionRequired = result.data['user_action_required'] == true;
      final securityLevel = switch (result.data['security_level']) {
        'critical' => AuraSecurityLevel.critical,
        'warning' => AuraSecurityLevel.warning,
        'safe' => AuraSecurityLevel.safe,
        _ => succeeded && !userActionRequired
            ? AuraSecurityLevel.safe
            : AuraSecurityLevel.warning,
      };
      _securityState?.setSecurityLevel(securityLevel);
      _emit(
        AgentEvent(
          kind: integrityCheckFailed
              ? AgentEventKind.error
              : succeeded && !userActionRequired
                  ? AgentEventKind.success
                  : AgentEventKind.warning,
          message: result.summary,
          data: result.data,
        ),
      );
      if (intent.kind == AuraIntentKind.updateDefenses && succeeded) {
        await _speakResponse(
          'Actualización completada. El modelo local de 500 árboles fue verificado e instalado.',
        );
      }
    } on Object catch (error) {
      _securityState?.setSecurityLevel(AuraSecurityLevel.warning);
      _emit(
        AgentEvent(
          kind: AgentEventKind.error,
          message: error.toString(),
          data: <String, dynamic>{'instruction': text},
        ),
      );
    }
  }

  Future<void> _speakResponse(String response) async {
    try {
      await _voiceEngine.speak(response);
    } on Object catch (error) {
      _emit(
        AgentEvent(
          kind: AgentEventKind.warning,
          message:
              'La respuesta está disponible en texto; falló la voz: $error',
          data: const <String, dynamic>{'component': 'flutter_tts'},
        ),
      );
    }
  }

  void reportError(String message) {
    _emit(AgentEvent(kind: AgentEventKind.error, message: message));
  }

  void reportWarning(String message) {
    _emit(AgentEvent(kind: AgentEventKind.warning, message: message));
  }

  void reportTerminalInput(String instruction) {
    _emit(
      AgentEvent(
        kind: AgentEventKind.thought,
        message: instruction,
        data: const <String, dynamic>{'terminal_prefix': '[USER]'},
      ),
    );
  }

  void reportTerminalThinking() {
    _emit(
      AgentEvent(
        kind: AgentEventKind.thought,
        message: 'PENSANDO...',
        data: const <String, dynamic>{
          'terminal_prefix': '[AURA]',
          'terminal_thinking': true,
        },
      ),
    );
  }

  void reportCriticalError(String message) {
    _securityState?.setSecurityLevel(AuraSecurityLevel.critical);
    _emit(
      AgentEvent(
        kind: AgentEventKind.error,
        message: message,
        data: const <String, dynamic>{
          'critical_integrity_failure': true,
          'security_level': 'critical',
        },
      ),
    );
  }

  /// Runs the native hostile-environment and anti-tampering probes (pillar 1)
  /// and reports the real result instead of a canned answer.
  Future<void> _runDeviceIntegrityCheck(AuraIntent intent) async {
    _emit(intent.toEvent());
    Map<String, dynamic> report;
    try {
      report = await _securityEngine.checkDeviceIntegrity();
    } catch (error) {
      _securityState?.setSecurityLevel(AuraSecurityLevel.warning);
      _emit(
        AgentEvent(
          kind: AgentEventKind.warning,
          message: 'No se pudo completar la comprobación de integridad: $error',
          data: const <String, dynamic>{'integrity_check_failed': true},
        ),
      );
      return;
    }
    final level = report['level'] as SystemThreatLevel?;
    final findings = <String>[
      if (report['rootBinaryFound'] == true) 'binario su',
      if (report['isDebuggerConnected'] == true) 'depurador conectado',
      if (report['fridaDetected'] == true) 'Frida',
      if (report['isVirtualEnvironment'] == true) 'entorno virtual',
      if (report['isEmulator'] == true) 'emulador',
      if (report['adbEnabled'] == true) 'ADB activo',
      if (report['signatureValid'] == false) 'firma no reconocida',
    ];
    _securityState?.setSecurityLevel(switch (level) {
      SystemThreatLevel.critical => AuraSecurityLevel.critical,
      SystemThreatLevel.warning => AuraSecurityLevel.warning,
      _ => AuraSecurityLevel.safe,
    });
    final summary =
        report['logs'] as String? ?? 'Comprobación de integridad completada.';
    final message = findings.isEmpty
        ? '$summary Son heurísticas locales; no sustituyen una atestación remota.'
        : '$summary Señales: ${findings.join(', ')}.';
    _emit(
      AgentEvent(
        kind: level == SystemThreatLevel.secure
            ? AgentEventKind.success
            : AgentEventKind.warning,
        message: message,
        data: <String, dynamic>{
          ...report,
          'level': level?.name,
        },
      ),
    );
    await _speakResponse(message);
  }

  void _emit(AgentEvent event) {
    history.add(event);
    if (history.length > maxHistoryLength) {
      history.removeRange(0, history.length - maxHistoryLength);
    }
    _eventController.add(event);
  }
}
