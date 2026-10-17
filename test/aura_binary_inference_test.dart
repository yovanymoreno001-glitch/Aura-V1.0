import 'dart:typed_data';

import 'package:aura_mobile_defens/inference/aura_binary_inference.dart';
import 'package:test/test.dart';

void main() {
  late Uint8List validMockModelBytes;
  late Uint8List corruptMockModelBytes;

  setUp(() {
    validMockModelBytes = _buildForest(<_TreeFixture>[
      _TreeFixture(
        rootIndex: 0,
        nodes: <_NodeFixture>[
          _NodeFixture.split(
            featureIndex: 5,
            threshold: 0.5,
            leftChild: 1,
            rightChild: 2,
          ),
          const _NodeFixture.leaf(0),
          const _NodeFixture.leaf(1),
        ],
      ),
      _TreeFixture(
        rootIndex: 0,
        nodes: <_NodeFixture>[
          _NodeFixture.split(
            featureIndex: 1,
            threshold: 3.5,
            leftChild: 1,
            rightChild: 2,
          ),
          const _NodeFixture.leaf(0),
          const _NodeFixture.leaf(1),
        ],
      ),
    ]);
    corruptMockModelBytes = Uint8List.fromList(<int>[
      0x42,
      0x42,
      0x42,
      0x42,
      0,
      0,
      0,
      0,
    ]);
  });

  group('AuraBinaryInference binary forest validation', () {
    test('allows official infrastructure through the static allowlist', () {
      expect(
        AuraBinaryInference.evaluateHostFromBinary(
          'google.com',
          validMockModelBytes,
        ),
        isTrue,
      );
      expect(
        AuraBinaryInference.evaluateHostFromBinary(
          'apple.com',
          validMockModelBytes,
        ),
        isTrue,
      );
    });

    test('rejects a threat vote from both indexed decision trees', () {
      expect(
        AuraBinaryInference.evaluateHostFromBinary(
          'x921llmzaqp0182ncnw.xyz',
          validMockModelBytes,
        ),
        isFalse,
      );
    });

    test('throws a controlled format exception for a corrupt magic signature',
        () {
      expect(
        () => AuraBinaryInference.evaluateHostFromBinary(
          'malicious-target.net',
          corruptMockModelBytes,
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('does not whitelist malformed URL-like input', () {
      expect(
        AuraBinaryInference.evaluateHostFromBinary(
          '://google.com',
          validMockModelBytes,
        ),
        isFalse,
      );
    });
  });
}

Uint8List _buildForest(List<_TreeFixture> trees) {
  final byteLength = 8 +
      trees.fold<int>(
        0,
        (length, tree) => length + 8 + tree.nodes.length * 20,
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

class _TreeFixture {
  const _TreeFixture({required this.rootIndex, required this.nodes});

  final int rootIndex;
  final List<_NodeFixture> nodes;
}

class _NodeFixture {
  const _NodeFixture.leaf(int classification)
      : type = 1,
        featureIndex = classification,
        leftChild = -1,
        rightChild = -1,
        threshold = 0;

  const _NodeFixture.split({
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
