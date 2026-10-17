import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

class AuraBinaryInference {
  static const List<String> auraStaticWhitelist = <String>[
    'google.com',
    'apple.com',
    'microsoft.com',
    'amazonaws.com',
    'cloudflare.com',
    'akamaiedge.net',
    'android.com',
    'github.com',
    'whatsapp.net',
    'googleapis.com',
    'gstatic.com',
    'googleusercontent.com',
    'apple-dns.net',
    'icloud.com',
    'microsoftonline.com',
    'windows.net',
    'amazon.com',
    'awsstatic.com',
    'akamaized.net',
    'fastly.net',
  ];

  static const List<String> suspiciousTlds = <String>[
    'biz',
    'xyz',
    'info',
    'cc',
    'top',
    'cam',
    'click',
    'country',
    'date',
    'download',
    'fit',
    'gq',
    'loan',
    'mov',
    'party',
    'review',
    'rest',
    'stream',
    'support',
    'tk',
    'wang',
    'work',
    'zip',
  ];

  static final RegExp _hostnamePattern = RegExp(
    r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
  );
  static const int _maximumTreeDepth = 32;
  static const int _binaryHeaderLength = 8;
  static const int _binaryTreeHeaderLength = 8;
  static const int _binaryNodeLength = 20;
  static const int _maximumBinaryModelBytes = 5 * 1024 * 1024;

  /// Returns true for allowlisted hosts or hosts classified as safe by the model.
  static bool analyzeHostSecure(
    String rawHost,
    Map<String, dynamic> trainedModelJson,
  ) {
    final host = _normalizeHost(rawHost);
    if (host == null) return false;
    if (_isAllowlisted(host)) return true;

    Uint8List? hostBuffer;
    Uint8List? frequencies;
    Float64List? features;
    try {
      hostBuffer = Uint8List.fromList(host.codeUnits);
      frequencies = Uint8List(128);
      features = Float64List(6);
      _extractFeatureVector(hostBuffer, frequencies, features);
      return _evaluateEnsemble(features, trainedModelJson);
    } finally {
      hostBuffer?.fillRange(0, hostBuffer.length, 0);
      frequencies?.fillRange(0, frequencies.length, 0);
      features?.fillRange(0, features.length, 0);
    }
  }

  /// Exposes the model's six feature values for diagnostics and verification.
  static Map<String, double> extractFeatures(String rawHost) {
    final host = _normalizeHost(rawHost);
    if (host == null) {
      throw const FormatException('El host no tiene un formato válido.');
    }

    Uint8List? hostBuffer;
    Uint8List? frequencies;
    Float64List? values;
    try {
      hostBuffer = Uint8List.fromList(host.codeUnits);
      frequencies = Uint8List(128);
      values = Float64List(6);
      _extractFeatureVector(hostBuffer, frequencies, values);
      return <String, double>{
        'length': values[0],
        'shannon_entropy': values[1],
        'digit_ratio': values[2],
        'vowel_ratio': values[3],
        'consonant_sequence_ratio': values[4],
        'suspicious_tld': values[5],
      };
    } finally {
      hostBuffer?.fillRange(0, hostBuffer.length, 0);
      frequencies?.fillRange(0, frequencies.length, 0);
      values?.fillRange(0, values.length, 0);
    }
  }

  /// Evaluates a little-endian AURA forest.
  ///
  /// Layout: `AURA`, uint32 tree count, then per tree uint32 root index and
  /// uint32 node count. Each node is five fields: int32 type (1 leaf, 2 split),
  /// int32 feature index (or leaf class 0/1), int32 left child, int32 right
  /// child, and float32 threshold. Child indices are local to their tree.
  static bool evaluateHostFromBinary(String rawHost, Uint8List modelBytes) {
    final host = _normalizeHost(rawHost);
    if (host == null) return false;
    if (_isAllowlisted(host)) return true;

    Uint8List? hostBuffer;
    Uint8List? frequencies;
    Float64List? features;
    try {
      if (modelBytes.length < _binaryHeaderLength ||
          modelBytes.length > _maximumBinaryModelBytes) {
        throw const FormatException('Tamaño de modelo binario no válido.');
      }

      final data = ByteData.sublistView(modelBytes);
      if (data.getUint8(0) != 0x41 ||
          data.getUint8(1) != 0x55 ||
          data.getUint8(2) != 0x52 ||
          data.getUint8(3) != 0x41) {
        throw const FormatException('La cabecera mágica AURA no es válida.');
      }

      final treeCount = data.getUint32(4, Endian.little);
      if (treeCount == 0 ||
          treeCount >
              (modelBytes.length - _binaryHeaderLength) ~/
                  _binaryTreeHeaderLength) {
        throw const FormatException('El conteo de árboles no es válido.');
      }

      hostBuffer = Uint8List.fromList(host.codeUnits);
      frequencies = Uint8List(128);
      features = Float64List(6);
      _extractFeatureVector(hostBuffer, frequencies, features);

      var offset = _binaryHeaderLength;
      var threatVotes = 0;
      for (var treeIndex = 0; treeIndex < treeCount; treeIndex++) {
        if (modelBytes.length - offset < _binaryTreeHeaderLength) {
          throw const FormatException('Cabecera de árbol truncada.');
        }
        final rootIndex = data.getUint32(offset, Endian.little);
        final nodeCount = data.getUint32(offset + 4, Endian.little);
        offset += _binaryTreeHeaderLength;

        if (nodeCount == 0 ||
            nodeCount > (modelBytes.length - offset) ~/ _binaryNodeLength) {
          throw const FormatException('Los nodos del árbol están truncados.');
        }
        final nodesStart = offset;
        _validateBinaryTree(data, nodesStart, nodeCount, rootIndex);
        final traversalPath = Uint8List(nodeCount);
        try {
          threatVotes += _walkBinaryTree(
            data,
            nodesStart,
            nodeCount,
            rootIndex,
            features,
            traversalPath,
          );
        } finally {
          traversalPath.fillRange(0, traversalPath.length, 0);
        }
        offset += nodeCount * _binaryNodeLength;
      }

      if (offset != modelBytes.length) {
        throw const FormatException('El modelo contiene bytes sobrantes.');
      }
      return threatVotes * 2 < treeCount;
    } finally {
      hostBuffer?.fillRange(0, hostBuffer.length, 0);
      frequencies?.fillRange(0, frequencies.length, 0);
      features?.fillRange(0, features.length, 0);
    }
  }

  /// Reads an indexed `.bin` model and clears the file buffer after evaluation.
  static Future<bool> evaluateHostFromBinaryFile(
    String rawHost,
    File modelFile,
  ) async {
    if (!modelFile.path.toLowerCase().endsWith('.bin')) {
      throw const FormatException('El modelo debe ser un archivo .bin.');
    }
    final fileLength = await modelFile.length();
    if (fileLength < _binaryHeaderLength ||
        fileLength > _maximumBinaryModelBytes) {
      throw const FormatException('Tamaño de modelo binario no válido.');
    }

    final modelBytes = await modelFile.readAsBytes();
    try {
      return evaluateHostFromBinary(rawHost, modelBytes);
    } finally {
      modelBytes.fillRange(0, modelBytes.length, 0);
    }
  }

  static void _validateBinaryTree(
    ByteData data,
    int nodesStart,
    int nodeCount,
    int rootIndex,
  ) {
    if (rootIndex >= nodeCount) {
      throw const FormatException('El índice raíz está fuera del árbol.');
    }

    for (var index = 0; index < nodeCount; index++) {
      final nodeOffset = nodesStart + index * _binaryNodeLength;
      final type = data.getInt32(nodeOffset, Endian.little);
      final featureIndex = data.getInt32(nodeOffset + 4, Endian.little);
      final leftChild = data.getInt32(nodeOffset + 8, Endian.little);
      final rightChild = data.getInt32(nodeOffset + 12, Endian.little);
      final threshold = data.getFloat32(nodeOffset + 16, Endian.little);

      if (type == 1) {
        if ((featureIndex != 0 && featureIndex != 1) ||
            leftChild != -1 ||
            rightChild != -1) {
          throw const FormatException('El nodo hoja binario no es válido.');
        }
      } else if (type == 2) {
        if (featureIndex < 0 ||
            featureIndex >= 6 ||
            leftChild < 0 ||
            leftChild >= nodeCount ||
            rightChild < 0 ||
            rightChild >= nodeCount ||
            !threshold.isFinite) {
          throw const FormatException(
              'El nodo de decisión binario no es válido.');
        }
      } else {
        throw const FormatException('Tipo de nodo binario desconocido.');
      }
    }
  }

  static int _walkBinaryTree(
    ByteData data,
    int nodesStart,
    int nodeCount,
    int nodeIndex,
    Float64List features,
    Uint8List traversalPath, [
    int depth = 0,
  ]) {
    if (depth > _maximumTreeDepth || nodeIndex < 0 || nodeIndex >= nodeCount) {
      throw const FormatException('Recorrido binario fuera de límites.');
    }
    if (traversalPath[nodeIndex] != 0) {
      throw const FormatException('El árbol binario contiene un ciclo.');
    }

    traversalPath[nodeIndex] = 1;
    try {
      final nodeOffset = nodesStart + nodeIndex * _binaryNodeLength;
      final type = data.getInt32(nodeOffset, Endian.little);
      final featureIndex = data.getInt32(nodeOffset + 4, Endian.little);
      if (type == 1) return featureIndex;

      final leftChild = data.getInt32(nodeOffset + 8, Endian.little);
      final rightChild = data.getInt32(nodeOffset + 12, Endian.little);
      final threshold = data.getFloat32(nodeOffset + 16, Endian.little);
      final childIndex =
          features[featureIndex] <= threshold ? leftChild : rightChild;
      return _walkBinaryTree(
        data,
        nodesStart,
        nodeCount,
        childIndex,
        features,
        traversalPath,
        depth + 1,
      );
    } finally {
      traversalPath[nodeIndex] = 0;
    }
  }

  static String? _normalizeHost(String rawInput) {
    var candidate = rawInput.trim().toLowerCase();
    if (candidate.isEmpty) return null;

    if (candidate.contains('://')) {
      final uri = Uri.tryParse(candidate);
      if (uri == null ||
          (uri.scheme != 'http' && uri.scheme != 'https') ||
          uri.userInfo.isNotEmpty ||
          uri.host.isEmpty) {
        return null;
      }
      candidate = uri.host.toLowerCase();
    } else if (candidate.contains(RegExp(r'[/\\?#@:%]'))) {
      return null;
    }

    if (candidate.endsWith('.')) {
      candidate = candidate.substring(0, candidate.length - 1);
    }
    if (!_hostnamePattern.hasMatch(candidate) ||
        InternetAddress.tryParse(candidate) != null) {
      return null;
    }
    return candidate;
  }

  static bool _isAllowlisted(String host) => auraStaticWhitelist.any(
        (suffix) => host == suffix || host.endsWith('.$suffix'),
      );

  static void _extractFeatureVector(
    Uint8List host,
    Uint8List frequencies,
    Float64List features,
  ) {
    final length = host.length;
    if (length == 0) return;

    var digits = 0;
    var vowels = 0;
    var letters = 0;
    var consonantRun = 0;
    var consonantSequenceCharacters = 0;
    var lastDot = -1;

    for (var index = 0; index < length; index++) {
      final character = host[index];
      frequencies[character]++;
      if (character == 0x2e) lastDot = index;
      if (character >= 0x30 && character <= 0x39) digits++;

      final lower = character | 0x20;
      final isLetter = (character >= 0x41 && character <= 0x5a) ||
          (character >= 0x61 && character <= 0x7a);
      if (!isLetter) {
        if (consonantRun >= 3) {
          consonantSequenceCharacters += consonantRun;
        }
        consonantRun = 0;
        continue;
      }

      letters++;
      if (lower == 0x61 ||
          lower == 0x65 ||
          lower == 0x69 ||
          lower == 0x6f ||
          lower == 0x75) {
        vowels++;
        if (consonantRun >= 3) {
          consonantSequenceCharacters += consonantRun;
        }
        consonantRun = 0;
      } else {
        consonantRun++;
      }
    }
    if (consonantRun >= 3) {
      consonantSequenceCharacters += consonantRun;
    }

    var entropy = 0.0;
    for (final count in frequencies) {
      if (count == 0) continue;
      final probability = count / length;
      entropy -= probability * (math.log(probability) / math.ln2);
    }

    features[0] = length.toDouble();
    features[1] = entropy;
    features[2] = digits / length;
    features[3] = letters == 0 ? 0 : vowels / letters;
    features[4] = letters == 0 ? 0 : consonantSequenceCharacters / letters;
    features[5] = _hasSuspiciousTld(host, lastDot) ? 1 : 0;
  }

  static bool _hasSuspiciousTld(Uint8List host, int lastDot) {
    if (lastDot < 0) return false;
    final tldLength = host.length - lastDot - 1;
    for (final tld in suspiciousTlds) {
      if (tld.length != tldLength) continue;
      var matches = true;
      for (var index = 0; index < tldLength; index++) {
        if (host[lastDot + 1 + index] != tld.codeUnitAt(index)) {
          matches = false;
          break;
        }
      }
      if (matches) return true;
    }
    return false;
  }

  static bool _evaluateEnsemble(
    Float64List features,
    Map<String, dynamic> model,
  ) {
    final trees = model['trees'];
    if (trees == null || (trees is List && trees.isEmpty)) return false;
    if (trees is! List) {
      throw const FormatException('El bosque de inferencia no es válido.');
    }

    var threatVotes = 0;
    for (final tree in trees) {
      if (tree is! Map || !tree.containsKey('root')) {
        throw const FormatException('La raíz de un árbol no es válida.');
      }
      threatVotes += _evaluateNode(tree['root'], features);
    }
    return threatVotes / trees.length < 0.5;
  }

  static int _evaluateNode(
    Object? rawNode,
    Float64List features, [
    int depth = 0,
  ]) {
    if (rawNode is! Map || depth > _maximumTreeDepth) {
      throw const FormatException('Nodo inválido en el modelo.');
    }
    if (rawNode['type'] == 'leaf') {
      final value = rawNode['value'];
      if (value is! int || (value != 0 && value != 1)) {
        throw const FormatException('La hoja debe contener un voto binario.');
      }
      return value;
    }

    final featureIndex = rawNode['feature_index'];
    final threshold = rawNode['threshold'];
    if (rawNode['type'] != 'split' ||
        featureIndex is! int ||
        featureIndex < 0 ||
        featureIndex >= features.length ||
        threshold is! num ||
        !threshold.toDouble().isFinite) {
      throw const FormatException('Nodo de bifurcación inválido.');
    }
    final branch = features[featureIndex] <= threshold.toDouble()
        ? rawNode['left']
        : rawNode['right'];
    return _evaluateNode(branch, features, depth + 1);
  }
}
