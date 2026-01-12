import 'dart:convert';

import 'package:rcspy/src/services/apk_analyzer.dart';
import 'package:rcspy/src/services/remote_config_service.dart';
import 'package:rcspy/src/services/supabase_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

class CachedAppData {
  final String packageId;
  // Firebase data
  final bool hasFirebase;
  final List<String> googleAppIds;
  final List<String> googleApiKeys;
  final bool? rcAccessible;
  final Map<String, dynamic>? rcConfigValues;
  // Supabase data
  final bool hasSupabase;
  final List<String> supabaseUrls;
  final List<String> supabaseAnonKeys;
  final bool? supabaseVulnerable;
  final Map<String, dynamic>? supabaseSecurityData;
  // Common
  final String? error;
  final DateTime analyzedAt;

  CachedAppData({
    required this.packageId,
    required this.hasFirebase,
    this.googleAppIds = const [],
    this.googleApiKeys = const [],
    this.rcAccessible,
    this.rcConfigValues,
    this.hasSupabase = false,
    this.supabaseUrls = const [],
    this.supabaseAnonKeys = const [],
    this.supabaseVulnerable,
    this.supabaseSecurityData,
    this.error,
    required this.analyzedAt,
  });

  bool get hasAnyBackend => hasFirebase || hasSupabase;
  bool get hasAnyVulnerability =>
      rcAccessible == true || supabaseVulnerable == true;

  Map<String, dynamic> toJson() => {
        'packageId': packageId,
        'hasFirebase': hasFirebase,
        'googleAppIds': googleAppIds,
        'googleApiKeys': googleApiKeys,
        'rcAccessible': rcAccessible,
        'rcConfigValues': rcConfigValues,
        'hasSupabase': hasSupabase,
        'supabaseUrls': supabaseUrls,
        'supabaseAnonKeys': supabaseAnonKeys,
        'supabaseVulnerable': supabaseVulnerable,
        'supabaseSecurityData': supabaseSecurityData,
        'error': error,
        'analyzedAt': analyzedAt.toIso8601String(),
      };

  factory CachedAppData.fromJson(Map<String, dynamic> json) {
    return CachedAppData(
      packageId: json['packageId'] as String,
      hasFirebase: json['hasFirebase'] as bool? ?? false,
      googleAppIds: List<String>.from(json['googleAppIds'] ?? []),
      googleApiKeys: List<String>.from(json['googleApiKeys'] ?? []),
      rcAccessible: json['rcAccessible'] as bool?,
      rcConfigValues: json['rcConfigValues'] != null
          ? Map<String, dynamic>.from(json['rcConfigValues'])
          : null,
      hasSupabase: json['hasSupabase'] as bool? ?? false,
      supabaseUrls: List<String>.from(json['supabaseUrls'] ?? []),
      supabaseAnonKeys: List<String>.from(json['supabaseAnonKeys'] ?? []),
      supabaseVulnerable: json['supabaseVulnerable'] as bool?,
      supabaseSecurityData: json['supabaseSecurityData'] != null
          ? Map<String, dynamic>.from(json['supabaseSecurityData'])
          : null,
      error: json['error'] as String?,
      analyzedAt: DateTime.parse(json['analyzedAt'] as String),
    );
  }

  FirebaseAnalysisResult toFirebaseResult() {
    if (error != null) {
      return FirebaseAnalysisResult.error(error!);
    }
    return FirebaseAnalysisResult(
      hasFirebase: hasFirebase,
      googleAppIds: googleAppIds,
      googleApiKeys: googleApiKeys,
    );
  }

  SupabaseAnalysisResult toSupabaseAnalysisResult() {
    if (error != null) {
      return SupabaseAnalysisResult.error(error!);
    }
    return SupabaseAnalysisResult(
      hasSupabase: hasSupabase,
      projectUrls: supabaseUrls,
      anonKeys: supabaseAnonKeys,
    );
  }

  ApkAnalysisResult toApkResult() {
    if (error != null) {
      return ApkAnalysisResult.error(error!);
    }
    return ApkAnalysisResult(
      firebase: toFirebaseResult(),
      supabase: toSupabaseAnalysisResult(),
    );
  }

  RemoteConfigResult? toRcResult() {
    if (rcAccessible == null) return null;
    if (rcAccessible!) {
      return RemoteConfigResult.accessible(rcConfigValues ?? {});
    }
    return RemoteConfigResult.secure();
  }

  SupabaseSecurityResult? toSupabaseSecurityResult() {
    if (supabaseVulnerable == null) return null;
    if (supabaseVulnerable!) {
      return SupabaseSecurityResult.fromMap(supabaseSecurityData ?? {});
    }
    return SupabaseSecurityResult.secure();
  }
}

class StorageService {
  static const String _cacheKey = 'analysis_cache';
  static const String _analyzedPackagesKey = 'analyzed_packages';

  static SharedPreferences? _prefs;

  static Future<void> init() async {
    _prefs = await SharedPreferences.getInstance();
  }

  static Map<String, CachedAppData> loadCache() {
    final prefs = _prefs;
    if (prefs == null) return {};

    final jsonString = prefs.getString(_cacheKey);
    if (jsonString == null) return {};

    try {
      final Map<String, dynamic> jsonMap = jsonDecode(jsonString);
      final cache = <String, CachedAppData>{};

      for (final entry in jsonMap.entries) {
        cache[entry.key] = CachedAppData.fromJson(
          Map<String, dynamic>.from(entry.value),
        );
      }

      return cache;
    } catch (e) {
      return {};
    }
  }

  static Future<void> saveAppData(CachedAppData data) async {
    final prefs = _prefs;
    if (prefs == null) return;

    final cache = loadCache();
    cache[data.packageId] = data;

    final jsonMap = cache.map((key, value) => MapEntry(key, value.toJson()));
    await prefs.setString(_cacheKey, jsonEncode(jsonMap));

    final analyzedPackages = getAnalyzedPackageIds();
    analyzedPackages.add(data.packageId);
    await prefs.setStringList(_analyzedPackagesKey, analyzedPackages.toList());
  }

  static Set<String> getAnalyzedPackageIds() {
    final prefs = _prefs;
    if (prefs == null) return {};

    final list = prefs.getStringList(_analyzedPackagesKey);
    return list?.toSet() ?? {};
  }

  static Future<void> removeAppData(String packageId) async {
    final prefs = _prefs;
    if (prefs == null) return;

    final cache = loadCache();
    cache.remove(packageId);

    final jsonMap = cache.map((key, value) => MapEntry(key, value.toJson()));
    await prefs.setString(_cacheKey, jsonEncode(jsonMap));

    final analyzedPackages = getAnalyzedPackageIds();
    analyzedPackages.remove(packageId);
    await prefs.setStringList(_analyzedPackagesKey, analyzedPackages.toList());
  }

  static Future<void> clearCache() async {
    final prefs = _prefs;
    if (prefs == null) return;

    await prefs.remove(_cacheKey);
    await prefs.remove(_analyzedPackagesKey);
  }

  static CachedAppData? getAppData(String packageId) {
    final cache = loadCache();
    return cache[packageId];
  }
}
