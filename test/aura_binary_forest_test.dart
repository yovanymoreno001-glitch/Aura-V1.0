import 'dart:math' as math;
import 'dart:io';
import 'dart:typed_data';

import 'package:aura_mobile_defens/inference/aura_binary_inference.dart';
import 'package:test/test.dart';

void main() {
  final mockModelJson = <String, dynamic>{
    'trees': <Map<String, Object>>[
      <String, Object>{
        'root': <String, Object>{
          'type': 'split',
          'feature_index': 1,
          'threshold': 3.5,
          'left': <String, Object>{'type': 'leaf', 'value': 0},
          'right': <String, Object>{'type': 'leaf', 'value': 1},
        },
      },
      <String, Object>{
        'root': <String, Object>{
          'type': 'split',
          'feature_index': 5,
          'threshold': 0.5,
          'left': <String, Object>{'type': 'leaf', 'value': 0},
          'right': <String, Object>{'type': 'leaf', 'value': 1},
        },
      },
    ],
  };

  group('AuraBinaryInference feature calculations', () {
    test('computes all six features from the normalized host', () {
      final features = AuraBinaryInference.extractFeatures('ABBB3.XYZ');
      const length = 9;
      final expectedEntropy =
          -((3 / length) * (math.log(3 / length) / math.ln2) +
              6 * (1 / length) * (math.log(1 / length) / math.ln2));

      expect(features['length'], 9);
      expect(features['shannon_entropy'], closeTo(expectedEntropy, 1e-12));
      expect(features['digit_ratio'], closeTo(1 / 9, 1e-12));
      expect(features['vowel_ratio'], closeTo(1 / 7, 1e-12));
      expect(features['consonant_sequence_ratio'], closeTo(6 / 7, 1e-12));
      expect(features['suspicious_tld'], 1);
    });

    test('does not treat a suspicious-looking substring as the TLD', () {
      final features = AuraBinaryInference.extractFeatures('notxyz.example');

      expect(features['suspicious_tld'], 0);
    });
  });

  group('Operational robustness', () {
    test('allows clean official domains without allowing suffix bypasses', () {
      expect(
        AuraBinaryInference.analyzeHostSecure('google.com', mockModelJson),
        isTrue,
      );
      expect(
        AuraBinaryInference.analyzeHostSecure('whatsapp.net', mockModelJson),
        isTrue,
      );
      expect(
        AuraBinaryInference.analyzeHostSecure(
          'google.com.maliciousdomain.xyz',
          mockModelJson,
        ),
        isFalse,
      );
    });

    test('classifies high-entropy hosts with suspicious TLDs as threats', () {
      expect(
        AuraBinaryInference.analyzeHostSecure(
          'x921llmzaqp0182ncnw.xyz',
          mockModelJson,
        ),
        isFalse,
      );
    });

    test('rejects empty and malformed hosts', () {
      expect(AuraBinaryInference.analyzeHostSecure('', mockModelJson), isFalse);
      expect(
        AuraBinaryInference.analyzeHostSecure('://google.com', mockModelJson),
        isFalse,
      );
    });

    test('rejects user-info tricks whose actual host is not allowlisted', () {
      expect(
        AuraBinaryInference.analyzeHostSecure(
          'https://google.com@attacker.xyz',
          mockModelJson,
        ),
        isFalse,
      );
    });
  });

  group('Allowlist boundary and ensemble decisions', () {
    test('checks all official suffixes and their subdomains', () {
      final threateningModel = _forest(<int>[1, 1, 1]);

      for (final suffix in AuraBinaryInference.auraStaticWhitelist) {
        expect(
          AuraBinaryInference.analyzeHostSecure(suffix, threateningModel),
          isTrue,
          reason: 'official suffix: $suffix',
        );
        expect(
          AuraBinaryInference.analyzeHostSecure('cdn.$suffix', threateningModel),
          isTrue,
          reason: 'official subdomain: cdn.$suffix',
        );
      }
      expect(
        AuraBinaryInference.analyzeHostSecure(
          'google.com.attacker.xyz',
          threateningModel,
        ),
        isFalse,
      );
    });

    test('uses a strict majority of tree votes', () {
      final tiedModel = _forest(<int>[1, 1, 0, 0]);
      final safeMajorityModel = _forest(<int>[1, 0, 0]);

      expect(
        AuraBinaryInference.analyzeHostSecure('ordinary.example', tiedModel),
        isFalse,
      );
      expect(
        AuraBinaryInference.analyzeHostSecure(
            'ordinary.example', safeMajorityModel),
        isTrue,
      );
    });

    test('rejects unverified hosts when no model is loaded', () {
      expect(
          AuraBinaryInference.analyzeHostSecure('ordinary.example', {}), isFalse);
    });
  });

  group('Binary AURA forest', () {
    test('walks nested nodes and applies little-endian thresholds', () {
      final model = _binaryForest(<_BinaryTree>[
        _BinaryTree(
          rootIndex: 0,
          nodes: <_BinaryNode>[
            _BinaryNode.split(
              featureIndex: 5,
              threshold: 0.5,
              leftChild: 1,
              rightChild: 2,
            ),
            const _BinaryNode.leaf(0),
            _BinaryNode.split(
              featureIndex: 0,
              threshold: 10.0,
              leftChild: 3,
              rightChild: 4,
            ),
            const _BinaryNode.leaf(0),
            const _BinaryNode.leaf(1),
          ],
        ),
      ]);

      expect(
        AuraBinaryInference.evaluateHostFromBinary('normal.example', model),
        isTrue,
      );
      expect(
        AuraBinaryInference.evaluateHostFromBinary('abcdefghijkl.xyz', model),
        isFalse,
      );
    });

    test('distinguishes little-endian float thresholds from byte-swapped data',
        () {
      final model = _binaryForest(<_BinaryTree>[
        _BinaryTree(
          rootIndex: 0,
          nodes: <_BinaryNode>[
            _BinaryNode.split(
              featureIndex: 2,
              threshold: 0.5,
              leftChild: 1,
              rightChild: 2,
            ),
            const _BinaryNode.leaf(0),
            const _BinaryNode.leaf(1),
          ],
        ),
      ]);

      expect(
        AuraBinaryInference.evaluateHostFromBinary('abc1.example', model),
        isTrue,
      );
    });

    test('loads and evaluates a .bin file', () async {
      final directory = await Directory.systemTemp.createTemp('aura-model-');
      try {
        final modelFile = File('${directory.path}/forest.bin');
        await modelFile.writeAsBytes(
          _binaryForest(<_BinaryTree>[_leafTree(0)]),
        );

        expect(
          await AuraBinaryInference.evaluateHostFromBinaryFile(
            'normal.example',
            modelFile,
          ),
          isTrue,
        );
      } finally {
        await directory.delete(recursive: true);
      }
    });

    test('uses threat votes and classifies a tie as threat', () {
      final tiedForest = _binaryForest(<_BinaryTree>[
        _leafTree(1),
        _leafTree(0),
      ]);
      final safeMajority = _binaryForest(<_BinaryTree>[
        _leafTree(1),
        _leafTree(0),
        _leafTree(0),
      ]);

      expect(
        AuraBinaryInference.evaluateHostFromBinary('normal.example', tiedForest),
        isFalse,
      );
      expect(
        AuraBinaryInference.evaluateHostFromBinary('normal.example', safeMajority),
        isTrue,
      );
    });

    test('accepts a threat leaf as the root of a tree', () {
      final model = _binaryForest(<_BinaryTree>[_leafTree(1)]);

      expect(
        AuraBinaryInference.evaluateHostFromBinary('normal.example', model),
        isFalse,
      );
    });

    test('rejects invalid magic, truncated records, and trailing bytes', () {
      final validModel = _binaryForest(<_BinaryTree>[_leafTree(0)]);
      final invalidMagic = Uint8List.fromList(validModel)..[0] = 0;
      final truncated = Uint8List.sublistView(
        validModel,
        0,
        validModel.length - 1,
      );
      final trailingByte = Uint8List(validModel.length + 1)
        ..setRange(0, validModel.length, validModel);

      expect(
        () => AuraBinaryInference.evaluateHostFromBinary(
          'normal.example',
          invalidMagic,
        ),
        throwsFormatException,
      );
      expect(
        () =>
            AuraBinaryInference.evaluateHostFromBinary('normal.example', truncated),
        throwsFormatException,
      );
      expect(
        () => AuraBinaryInference.evaluateHostFromBinary(
          'normal.example',
          trailingByte,
        ),
        throwsFormatException,
      );
    });

    test('rejects cyclic trees and invalid feature indexes', () {
      final cyclicForest = _binaryForest(<_BinaryTree>[
        _BinaryTree(
          rootIndex: 0,
          nodes: <_BinaryNode>[
            _BinaryNode.split(
              featureIndex: 5,
              threshold: 0.5,
              leftChild: 0,
              rightChild: 1,
            ),
            const _BinaryNode.leaf(0),
          ],
        ),
      ]);
      final invalidFeatureForest = _binaryForest(<_BinaryTree>[
        _BinaryTree(
          rootIndex: 0,
          nodes: <_BinaryNode>[
            _BinaryNode.split(
              featureIndex: 6,
              threshold: 0.5,
              leftChild: 1,
              rightChild: 1,
            ),
            const _BinaryNode.leaf(0),
          ],
        ),
      ]);

      expect(
        () => AuraBinaryInference.evaluateHostFromBinary(
          'normal.example',
          cyclicForest,
        ),
        throwsFormatException,
      );
      expect(
        () => AuraBinaryInference.evaluateHostFromBinary(
          'normal.example',
          invalidFeatureForest,
        ),
        throwsFormatException,
      );
    });
  });
}

Map<String, dynamic> _forest(List<int> leafVotes) => <String, dynamic>{
      'trees': <Map<String, Object>>[
        for (final vote in leafVotes)
          <String, Object>{
            'root': <String, Object>{'type': 'leaf', 'value': vote},
          },
      ],
    };

Uint8List _binaryForest(List<_BinaryTree> trees) {
  final byteLength = 8 +
      trees.fold<int>(
        0,
        (total, tree) => total + 8 + tree.nodes.length * 20,
      );
  final bytes = Uint8List(byteLength);
  final data = ByteData.sublistView(bytes);
  data
    ..setUint8(0, 0x41)
    ..setUint8(1, 0x55)
    ..setUint8(2, 0x52)
    ..setUint8(3, 0x41)
    ..setUint32(4, trees.length, Endian.little);

  var offset = 8;
  for (final tree in trees) {
    data
      ..setUint32(offset, tree.rootIndex, Endian.little)
      ..setUint32(offset + 4, tree.nodes.length, Endian.little);
    offset += 8;
    for (final node in tree.nodes) {
      data
        ..setInt32(offset, node.type, Endian.little)
        ..setInt32(offset + 4, node.featureIndex, Endian.little)
        ..setInt32(offset + 8, node.leftChild, Endian.little)
        ..setInt32(offset + 12, node.rightChild, Endian.little)
        ..setFloat32(offset + 16, node.threshold, Endian.little);
      offset += 20;
    }
  }
  return bytes;
}

_BinaryTree _leafTree(int classification) => _BinaryTree(
      rootIndex: 0,
      nodes: <_BinaryNode>[_BinaryNode.leaf(classification)],
    );

class _BinaryTree {
  const _BinaryTree({required this.rootIndex, required this.nodes});

  final int rootIndex;
  final List<_BinaryNode> nodes;
}

class _BinaryNode {
  const _BinaryNode.leaf(int classification)
      : type = 1,
        featureIndex = classification,
        leftChild = -1,
        rightChild = -1,
        threshold = 0;

  const _BinaryNode.split({
    required this.featureIndex,
    required this.threshold,
    required this.leftChild,
    required this.rightChild,
  }) : type = 2;

  final int type;
  final int featureIndex;
  final int leftChild;
  final int rightChild;
  final double threshold;
}
