import 'package:aura_mobile_defens/network_auditor.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('NetworkAuditEvent.fromPlatform', () {
    Map<String, Object> raw(String action) => {
          'timestamp': 1791835200000,
          'source_app': 'com.android.chrome',
          'requested_domain': 'cloudflare-ech.com',
          'action': action,
        };

    test('maps every native action emitted by AuraNetworkStream', () {
      expect(NetworkAuditEvent.fromPlatform(raw('BLOCKED')).action,
          NetworkAuditAction.blocked);
      expect(NetworkAuditEvent.fromPlatform(raw('DGA_ALERT')).action,
          NetworkAuditAction.dgaAlert);
      expect(NetworkAuditEvent.fromPlatform(raw('ALLOWED')).action,
          NetworkAuditAction.allowed);
      expect(NetworkAuditEvent.fromPlatform(raw('ECH_OBSERVED')).action,
          NetworkAuditAction.echObserved);
    });

    test('round-trips ECH events through toJson', () {
      final json = NetworkAuditEvent.fromPlatform(raw('ECH_OBSERVED')).toJson();
      expect(json['action'], 'ECH_OBSERVED');
      expect(json['requested_domain'], 'cloudflare-ech.com');
    });

    test('rejects unknown actions and non-map payloads', () {
      expect(() => NetworkAuditEvent.fromPlatform(raw('DROP_TABLE')),
          throwsFormatException);
      expect(() => NetworkAuditEvent.fromPlatform('BLOCKED'),
          throwsFormatException);
    });
  });
}
