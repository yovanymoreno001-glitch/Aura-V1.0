import 'agent_controller.dart';
import 'agent_event.dart';

/// Intent categories reported to the console UI after a command runs.
///
/// Natural-language parsing lives in [AuraIntentParser] (aura_intent_parser.dart);
/// this file only executes a command through [AgentController] and maps the
/// resulting event for display.
enum AuraCommandIntent {
  blockDomain,
  isolateApp,
  panicIsolation,
  resumeNetwork,
  cryptographicPurge,
  updateModel,
  conversation,
  status,
  unknown,
}

class AuraCommandExecutor {
  AuraCommandExecutor._();

  static Future<Map<String, dynamic>> executeCommand(String input) async {
    final command = input.trim();
    if (command.isEmpty) {
      return <String, dynamic>{
        'intent': AuraCommandIntent.unknown,
        'success': false,
        'response': '[WARN] Escribe una orden o consulta antes de enviarla.',
      };
    }

    final controller = AgentController.instance;
    final previousEvents = Set<AgentEvent>.identity()
      ..addAll(controller.history);
    try {
      await controller.run(command);
    } on Object catch (error) {
      final response = '[CRIT] No se pudo ejecutar la orden: $error';
      controller.reportError(response);
      return <String, dynamic>{
        'intent': AuraCommandIntent.unknown,
        'success': false,
        'response': response,
        'event': controller.history.last,
      };
    }

    final generatedEvents = controller.history
        .where((event) => !previousEvents.contains(event))
        .toList(growable: false);
    final responseEvent = generatedEvents.isEmpty ? null : generatedEvents.last;
    if (responseEvent == null) {
      const response = '[WARN] No se generó un resultado para la orden.';
      controller.reportError(response);
      return <String, dynamic>{
        'intent': AuraCommandIntent.unknown,
        'success': false,
        'response': response,
        'event': controller.history.last,
      };
    }

    final intentEvent = generatedEvents.firstWhere(
      (event) => event.data?['confidence'] is num,
      orElse: () => responseEvent,
    );
    final responseData = responseEvent.data;
    final intentName = responseData?['protected_host'] == true ||
            responseData?['allowlist_check_failed'] == true
        ? 'block_domain'
        : responseEvent.kind == AgentEventKind.warning &&
                responseData?['instruction'] is String &&
                identical(intentEvent, responseEvent)
            ? 'unknown'
            : (responseData?['intent'] as String?) ?? intentEvent.message;
    final intent = _intentFromName(intentName);
    final prefix = switch (responseEvent.kind) {
      AgentEventKind.success => '[OK]',
      AgentEventKind.warning ||
      AgentEventKind.thought ||
      AgentEventKind.action =>
        '[WARN]',
      AgentEventKind.error => '[CRIT]',
    };

    return <String, dynamic>{
      'intent': intent,
      'success': responseEvent.kind == AgentEventKind.success,
      'response': '$prefix ${responseEvent.message}',
      'event': responseEvent,
    };
  }

  static AuraCommandIntent _intentFromName(String name) => switch (name) {
        'block_domain' => AuraCommandIntent.blockDomain,
        'isolate_app' => AuraCommandIntent.isolateApp,
        'panic_isolation' => AuraCommandIntent.panicIsolation,
        'resume_network' => AuraCommandIntent.resumeNetwork,
        'cryptographic_purge' => AuraCommandIntent.cryptographicPurge,
        'update_defenses' => AuraCommandIntent.updateModel,
        'status' => AuraCommandIntent.status,
        'unknown' => AuraCommandIntent.unknown,
        _ => AuraCommandIntent.conversation,
      };
}
