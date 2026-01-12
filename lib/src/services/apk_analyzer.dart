import 'dart:io';
import 'dart:isolate';

import 'package:archive/archive.dart';

class FirebaseAnalysisResult {
  final bool hasFirebase;
  final List<String> googleAppIds;
  final List<String> googleApiKeys;
  final String? error;

  FirebaseAnalysisResult({
    required this.hasFirebase,
    this.googleAppIds = const [],
    this.googleApiKeys = const [],
    this.error,
  });

  factory FirebaseAnalysisResult.error(String message) {
    return FirebaseAnalysisResult(
      hasFirebase: false,
      googleAppIds: [],
      googleApiKeys: [],
      error: message,
    );
  }

  Map<String, dynamic> toMap() => {
        'hasFirebase': hasFirebase,
        'googleAppIds': googleAppIds,
        'googleApiKeys': googleApiKeys,
        'error': error,
      };

  factory FirebaseAnalysisResult.fromMap(Map<String, dynamic> map) {
    return FirebaseAnalysisResult(
      hasFirebase: map['hasFirebase'] as bool,
      googleAppIds: List<String>.from(map['googleAppIds'] ?? []),
      googleApiKeys: List<String>.from(map['googleApiKeys'] ?? []),
      error: map['error'] as String?,
    );
  }
}

class SupabaseAnalysisResult {
  final bool hasSupabase;
  final List<String> projectUrls;
  final List<String> anonKeys;
  final String? error;

  SupabaseAnalysisResult({
    required this.hasSupabase,
    this.projectUrls = const [],
    this.anonKeys = const [],
    this.error,
  });

  factory SupabaseAnalysisResult.error(String message) {
    return SupabaseAnalysisResult(
      hasSupabase: false,
      projectUrls: [],
      anonKeys: [],
      error: message,
    );
  }

  factory SupabaseAnalysisResult.none() {
    return SupabaseAnalysisResult(
      hasSupabase: false,
      projectUrls: [],
      anonKeys: [],
    );
  }

  Map<String, dynamic> toMap() => {
        'hasSupabase': hasSupabase,
        'projectUrls': projectUrls,
        'anonKeys': anonKeys,
        'error': error,
      };

  factory SupabaseAnalysisResult.fromMap(Map<String, dynamic> map) {
    return SupabaseAnalysisResult(
      hasSupabase: map['hasSupabase'] as bool? ?? false,
      projectUrls: List<String>.from(map['projectUrls'] ?? []),
      anonKeys: List<String>.from(map['anonKeys'] ?? []),
      error: map['error'] as String?,
    );
  }
}

class ApkAnalysisResult {
  final FirebaseAnalysisResult firebase;
  final SupabaseAnalysisResult supabase;
  final String? error;

  ApkAnalysisResult({
    required this.firebase,
    required this.supabase,
    this.error,
  });

  bool get hasAnyBackend => firebase.hasFirebase || supabase.hasSupabase;

  factory ApkAnalysisResult.error(String message) {
    return ApkAnalysisResult(
      firebase: FirebaseAnalysisResult.error(message),
      supabase: SupabaseAnalysisResult.error(message),
      error: message,
    );
  }

  Map<String, dynamic> toMap() => {
        'firebase': firebase.toMap(),
        'supabase': supabase.toMap(),
        'error': error,
      };

  factory ApkAnalysisResult.fromMap(Map<String, dynamic> map) {
    return ApkAnalysisResult(
      firebase: FirebaseAnalysisResult.fromMap(
        Map<String, dynamic>.from(map['firebase'] ?? {'hasFirebase': false}),
      ),
      supabase: SupabaseAnalysisResult.fromMap(
        Map<String, dynamic>.from(map['supabase'] ?? {'hasSupabase': false}),
      ),
      error: map['error'] as String?,
    );
  }
}

Future<Map<String, dynamic>> _analyzeApkInIsolate(String apkPath) async {
  try {
    final file = File(apkPath);

    if (!await file.exists()) {
      return ApkAnalysisResult.error('APK file not found').toMap();
    }

    final bytes = await file.readAsBytes();

    final archive = ZipDecoder().decodeBytes(bytes);

    // Firebase patterns
    final Set<String> foundAppIds = {};
    final Set<String> foundApiKeys = {};

    // Supabase patterns
    final Set<String> foundSupabaseUrls = {};
    final Set<String> foundSupabaseKeys = {};

    final googleAppIdPattern = RegExp(
      r'\d+:\d+:android:[a-f0-9]+',
      caseSensitive: false,
    );
    final googleApiKeyPattern = RegExp(
      r'AIza[0-9A-Za-z_-]{35}',
    );

    // Supabase URL pattern: https://<project-ref>.supabase.co
    final supabaseUrlPattern = RegExp(
      r'https?://[a-z0-9-]+\.supabase\.co',
      caseSensitive: false,
    );

    // Supabase anon/publishable key patterns:
    // Old format (JWT): eyJ<base64>.<base64>.<base64>
    // New format: sb_publishable_<key> or sb_secret_<key>
    final supabaseKeyPatternJWT = RegExp(
      r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}',
    );
    final supabaseKeyPatternNew = RegExp(
      r'sb_(publishable|secret)_[A-Za-z0-9_-]{20,}',
    );

    for (final archiveFile in archive) {
      if (archiveFile.isFile) {
        final fileName = archiveFile.name.toLowerCase();

        if (_shouldAnalyzeFileStatic(fileName)) {
          final content = archiveFile.content as List<int>;
          final extractedData = _extractAllCredentialsStatic(
            content,
            googleAppIdPattern,
            googleApiKeyPattern,
            supabaseUrlPattern,
            supabaseKeyPatternJWT,
            supabaseKeyPatternNew,
          );
          foundAppIds.addAll(extractedData.firebaseAppIds);
          foundApiKeys.addAll(extractedData.firebaseApiKeys);
          foundSupabaseUrls.addAll(extractedData.supabaseUrls);
          foundSupabaseKeys.addAll(extractedData.supabaseKeys);
        }
      }
    }

    final hasFirebase = foundAppIds.isNotEmpty || foundApiKeys.isNotEmpty;
    // Detect Supabase if URL OR key found (security check requires both)
    final hasSupabase = foundSupabaseUrls.isNotEmpty || foundSupabaseKeys.isNotEmpty;

    return ApkAnalysisResult(
      firebase: FirebaseAnalysisResult(
        hasFirebase: hasFirebase,
        googleAppIds: foundAppIds.toList(),
        googleApiKeys: foundApiKeys.toList(),
      ),
      supabase: SupabaseAnalysisResult(
        hasSupabase: hasSupabase,
        projectUrls: foundSupabaseUrls.toList(),
        anonKeys: foundSupabaseKeys.toList(),
      ),
    ).toMap();
  } catch (e) {
    return ApkAnalysisResult.error('Failed to analyze APK: $e').toMap();
  }
}

bool _shouldAnalyzeFileStatic(String fileName) {
  return fileName.endsWith('.arsc') ||
      fileName.endsWith('.xml') ||
      fileName.endsWith('.json') ||
      fileName.endsWith('.dex') ||
      fileName.endsWith('.properties') ||
      fileName.endsWith('.so') || // Flutter apps store strings in native libs
      fileName.contains('google-services') ||
      fileName.contains('firebase') ||
      fileName.contains('supabase') ||
      fileName.contains('config');
}

class _ExtractedCredentials {
  final Set<String> firebaseAppIds;
  final Set<String> firebaseApiKeys;
  final Set<String> supabaseUrls;
  final Set<String> supabaseKeys;

  _ExtractedCredentials({
    required this.firebaseAppIds,
    required this.firebaseApiKeys,
    required this.supabaseUrls,
    required this.supabaseKeys,
  });
}

_ExtractedCredentials _extractAllCredentialsStatic(
  List<int> content,
  RegExp firebaseAppIdPattern,
  RegExp firebaseApiKeyPattern,
  RegExp supabaseUrlPattern,
  RegExp supabaseKeyPatternJWT,
  RegExp supabaseKeyPatternNew,
) {
  final Set<String> foundFirebaseAppIds = {};
  final Set<String> foundFirebaseApiKeys = {};
  final Set<String> foundSupabaseUrls = {};
  final Set<String> foundSupabaseKeys = {};

  try {
    final stringContent = _extractStringsFromBytesStatic(content);

    // Firebase credentials
    final appIdMatches = firebaseAppIdPattern.allMatches(stringContent);
    for (final match in appIdMatches) {
      foundFirebaseAppIds.add(match.group(0)!);
    }

    final apiKeyMatches = firebaseApiKeyPattern.allMatches(stringContent);
    for (final match in apiKeyMatches) {
      foundFirebaseApiKeys.add(match.group(0)!);
    }

    // Supabase credentials
    final supabaseUrlMatches = supabaseUrlPattern.allMatches(stringContent);
    for (final match in supabaseUrlMatches) {
      foundSupabaseUrls.add(match.group(0)!);
    }

    // Old JWT format keys
    final supabaseKeyMatchesJWT = supabaseKeyPatternJWT.allMatches(stringContent);
    for (final match in supabaseKeyMatchesJWT) {
      final key = match.group(0)!;
      if (_isLikelySupabaseKeyJWT(key)) {
        foundSupabaseKeys.add(key);
      }
    }

    // New sb_publishable/sb_secret format keys
    final supabaseKeyMatchesNew = supabaseKeyPatternNew.allMatches(stringContent);
    for (final match in supabaseKeyMatchesNew) {
      foundSupabaseKeys.add(match.group(0)!);
    }
  } catch (e) {
    // Ignore extraction errors
  }

  return _ExtractedCredentials(
    firebaseAppIds: foundFirebaseAppIds,
    firebaseApiKeys: foundFirebaseApiKeys,
    supabaseUrls: foundSupabaseUrls,
    supabaseKeys: foundSupabaseKeys,
  );
}

bool _isLikelySupabaseKeyJWT(String jwt) {
  try {
    final parts = jwt.split('.');
    if (parts.length != 3) return false;

    // Decode the payload (second part)
    String payload = parts[1];
    // Add padding if needed
    while (payload.length % 4 != 0) {
      payload += '=';
    }
    // Replace URL-safe characters
    payload = payload.replaceAll('-', '+').replaceAll('_', '/');

    // Decode base64 and check for Supabase-specific fields
    final decodedBytes = _base64Decode(payload);
    if (decodedBytes == null) return false;

    final decodedStr = String.fromCharCodes(decodedBytes);

    // Check for Supabase-specific indicators in the JWT payload:
    // - "iss" containing "supabase"
    // - "role" field (anon, authenticated, service_role)
    // - "ref" field (project reference)
    final isSupabase = decodedStr.contains('"iss"') &&
        (decodedStr.contains('supabase') ||
         decodedStr.contains('"role":"anon"') ||
         decodedStr.contains('"role":"service_role"') ||
         decodedStr.contains('"role":"authenticated"'));

    return isSupabase;
  } catch (e) {
    return false;
  }
}

List<int>? _base64Decode(String input) {
  try {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    final bytes = <int>[];
    int buffer = 0;
    int bitsCollected = 0;

    for (int i = 0; i < input.length; i++) {
      final char = input[i];
      if (char == '=') break;
      final value = chars.indexOf(char);
      if (value == -1) continue;

      buffer = (buffer << 6) | value;
      bitsCollected += 6;

      if (bitsCollected >= 8) {
        bitsCollected -= 8;
        bytes.add((buffer >> bitsCollected) & 0xFF);
      }
    }

    return bytes;
  } catch (e) {
    return null;
  }
}

String _extractStringsFromBytesStatic(List<int> bytes) {
  final buffer = StringBuffer();
  final currentString = StringBuffer();

  for (final byte in bytes) {
    if (byte >= 32 && byte <= 126) {
      currentString.writeCharCode(byte);
    } else {
      if (currentString.length >= 4) {
        buffer.write(currentString.toString());
        buffer.write(' ');
      }
      currentString.clear();
    }
  }

  if (currentString.length >= 4) {
    buffer.write(currentString.toString());
  }

  return buffer.toString();
}

class ApkAnalyzer {
  static Future<ApkAnalysisResult> analyzeApk(String apkPath) async {
    try {
      final resultMap = await Isolate.run(() => _analyzeApkInIsolate(apkPath));
      return ApkAnalysisResult.fromMap(resultMap);
    } catch (e) {
      return ApkAnalysisResult.error('Isolate error: $e');
    }
  }

  // Legacy method for backwards compatibility
  static Future<FirebaseAnalysisResult> analyzeApkFirebaseOnly(
      String apkPath) async {
    final result = await analyzeApk(apkPath);
    return result.firebase;
  }
}
