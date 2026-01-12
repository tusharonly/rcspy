import 'dart:convert';

import 'package:http/http.dart' as http;

class SupabaseCredentials {
  final List<String> projectUrls;
  final List<String> anonKeys;

  SupabaseCredentials({
    this.projectUrls = const [],
    this.anonKeys = const [],
  });

  bool get hasSupabase => projectUrls.isNotEmpty && anonKeys.isNotEmpty;

  Map<String, dynamic> toMap() => {
        'projectUrls': projectUrls,
        'anonKeys': anonKeys,
      };

  factory SupabaseCredentials.fromMap(Map<String, dynamic> map) {
    return SupabaseCredentials(
      projectUrls: List<String>.from(map['projectUrls'] ?? []),
      anonKeys: List<String>.from(map['anonKeys'] ?? []),
    );
  }
}

class StorageBucketInfo {
  final String id;
  final String name;
  final bool isPublic;
  final List<String> exposedFiles;

  StorageBucketInfo({
    required this.id,
    required this.name,
    required this.isPublic,
    this.exposedFiles = const [],
  });

  Map<String, dynamic> toMap() => {
        'id': id,
        'name': name,
        'isPublic': isPublic,
        'exposedFiles': exposedFiles,
      };

  factory StorageBucketInfo.fromMap(Map<String, dynamic> map) {
    return StorageBucketInfo(
      id: map['id'] as String,
      name: map['name'] as String,
      isPublic: map['isPublic'] as bool? ?? map['public'] as bool? ?? false,
      exposedFiles: List<String>.from(map['exposedFiles'] ?? []),
    );
  }
}

class ExposedTableInfo {
  final String tableName;
  final int? rowCount;
  final List<String> columns;
  final List<Map<String, dynamic>> sampleData;

  ExposedTableInfo({
    required this.tableName,
    this.rowCount,
    this.columns = const [],
    this.sampleData = const [],
  });

  Map<String, dynamic> toMap() => {
        'tableName': tableName,
        'rowCount': rowCount,
        'columns': columns,
        'sampleData': sampleData,
      };

  factory ExposedTableInfo.fromMap(Map<String, dynamic> map) {
    return ExposedTableInfo(
      tableName: map['tableName'] as String,
      rowCount: map['rowCount'] as int?,
      columns: List<String>.from(map['columns'] ?? []),
      sampleData: (map['sampleData'] as List?)
              ?.map((e) => Map<String, dynamic>.from(e))
              .toList() ??
          [],
    );
  }
}

class SupabaseSecurityResult {
  final bool isVulnerable;
  final String? workingProjectUrl;
  final String? workingAnonKey;
  final List<StorageBucketInfo> publicBuckets;
  final List<StorageBucketInfo> allBuckets;
  final List<ExposedTableInfo> exposedTables;
  final List<String> exposedStorageObjects;
  final String? error;

  SupabaseSecurityResult({
    required this.isVulnerable,
    this.workingProjectUrl,
    this.workingAnonKey,
    this.publicBuckets = const [],
    this.allBuckets = const [],
    this.exposedTables = const [],
    this.exposedStorageObjects = const [],
    this.error,
  });

  factory SupabaseSecurityResult.secure() {
    return SupabaseSecurityResult(isVulnerable: false);
  }

  factory SupabaseSecurityResult.error(String message) {
    return SupabaseSecurityResult(
      isVulnerable: false,
      error: message,
    );
  }

  factory SupabaseSecurityResult.vulnerable({
    required String projectUrl,
    required String anonKey,
    List<StorageBucketInfo> publicBuckets = const [],
    List<StorageBucketInfo> allBuckets = const [],
    List<ExposedTableInfo> exposedTables = const [],
    List<String> exposedStorageObjects = const [],
  }) {
    return SupabaseSecurityResult(
      isVulnerable: true,
      workingProjectUrl: projectUrl,
      workingAnonKey: anonKey,
      publicBuckets: publicBuckets,
      allBuckets: allBuckets,
      exposedTables: exposedTables,
      exposedStorageObjects: exposedStorageObjects,
    );
  }

  Map<String, dynamic> toMap() => {
        'isVulnerable': isVulnerable,
        'workingProjectUrl': workingProjectUrl,
        'workingAnonKey': workingAnonKey,
        'publicBuckets': publicBuckets.map((b) => b.toMap()).toList(),
        'allBuckets': allBuckets.map((b) => b.toMap()).toList(),
        'exposedTables': exposedTables.map((t) => t.toMap()).toList(),
        'exposedStorageObjects': exposedStorageObjects,
        'error': error,
      };

  factory SupabaseSecurityResult.fromMap(Map<String, dynamic> map) {
    return SupabaseSecurityResult(
      isVulnerable: map['isVulnerable'] as bool? ?? false,
      workingProjectUrl: map['workingProjectUrl'] as String?,
      workingAnonKey: map['workingAnonKey'] as String?,
      publicBuckets: (map['publicBuckets'] as List?)
              ?.map((e) => StorageBucketInfo.fromMap(Map<String, dynamic>.from(e)))
              .toList() ??
          [],
      allBuckets: (map['allBuckets'] as List?)
              ?.map((e) => StorageBucketInfo.fromMap(Map<String, dynamic>.from(e)))
              .toList() ??
          [],
      exposedTables: (map['exposedTables'] as List?)
              ?.map((e) => ExposedTableInfo.fromMap(Map<String, dynamic>.from(e)))
              .toList() ??
          [],
      exposedStorageObjects:
          List<String>.from(map['exposedStorageObjects'] ?? []),
      error: map['error'] as String?,
    );
  }
}

class SupabaseService {
  static const List<String> _commonTableNames = [
    // User/Auth related
    'users',
    'profiles',
    'accounts',
    'customers',
    'members',
    'admins',
    'user_profiles',
    'user_data',
    'users_exposed',
    // Content
    'posts',
    'comments',
    'messages',
    'articles',
    'content',
    'media',
    // E-commerce
    'orders',
    'products',
    'items',
    'cart',
    'payments',
    'transactions',
    'invoices',
    // Files/Documents
    'documents',
    'files',
    'uploads',
    'attachments',
    'images',
    'backups',
    // Config/Settings
    'settings',
    'config',
    'app_config',
    'configurations',
    'preferences',
    'options',
    // Data/Logs
    'data',
    'logs',
    'events',
    'analytics',
    'metrics',
    'audit_logs',
    // Notifications
    'notifications',
    'alerts',
    'emails',
    // Sessions/Auth
    'sessions',
    'tokens',
    'api_keys',
    'credentials',
    'auth_tokens',
    // Security-sensitive (test for vulnerabilities)
    'secrets',
    'test_secrets',
    'keys',
    'passwords',
    'private',
    'sensitive',
    'internal',
    // Generic
    'records',
    'entries',
    'info',
    'metadata',
    'public',
    'test',
    'demo',
    'sample',
  ];

  static Future<SupabaseSecurityResult> checkSecurity({
    required String projectUrl,
    required String anonKey,
  }) async {
    try {
      final normalizedUrl = _normalizeProjectUrl(projectUrl);

      final headers = {
        'apikey': anonKey,
        'Authorization': 'Bearer $anonKey',
      };

      final List<StorageBucketInfo> allBuckets = [];
      final List<StorageBucketInfo> publicBuckets = [];
      final List<ExposedTableInfo> exposedTables = [];
      final List<String> exposedStorageObjects = [];

      // Check storage buckets
      final bucketsResult = await _checkStorageBuckets(normalizedUrl, headers);
      allBuckets.addAll(bucketsResult);
      publicBuckets.addAll(bucketsResult.where((b) => b.isPublic));

      // Check for exposed storage objects via REST API
      final storageObjects = await _checkStorageObjects(normalizedUrl, headers);
      exposedStorageObjects.addAll(storageObjects);

      // Check for exposed tables
      final tables = await _checkExposedTables(normalizedUrl, headers);
      exposedTables.addAll(tables);

      final isVulnerable = publicBuckets.isNotEmpty ||
          exposedTables.isNotEmpty ||
          exposedStorageObjects.isNotEmpty;

      if (isVulnerable) {
        return SupabaseSecurityResult.vulnerable(
          projectUrl: normalizedUrl,
          anonKey: anonKey,
          publicBuckets: publicBuckets,
          allBuckets: allBuckets,
          exposedTables: exposedTables,
          exposedStorageObjects: exposedStorageObjects,
        );
      }

      return SupabaseSecurityResult.secure();
    } catch (e) {
      return SupabaseSecurityResult.error('Failed to check Supabase: $e');
    }
  }

  static Future<List<StorageBucketInfo>> _checkStorageBuckets(
    String projectUrl,
    Map<String, String> headers,
  ) async {
    final buckets = <StorageBucketInfo>[];

    try {
      final url = Uri.parse('$projectUrl/storage/v1/bucket');
      final response = await http.get(url, headers: headers).timeout(
            const Duration(seconds: 10),
          );

      if (response.statusCode == 200) {
        final List<dynamic> data = jsonDecode(response.body);
        for (final bucket in data) {
          final bucketInfo = StorageBucketInfo(
            id: bucket['id'] as String? ?? '',
            name: bucket['name'] as String? ?? '',
            isPublic: bucket['public'] as bool? ?? false,
          );
          buckets.add(bucketInfo);
        }
      }
    } catch (e) {
      // Bucket listing failed - might not have permission
    }

    return buckets;
  }

  static Future<List<String>> _checkStorageObjects(
    String projectUrl,
    Map<String, String> headers,
  ) async {
    final objects = <String>[];

    try {
      // Try to query storage.objects via REST API
      final url = Uri.parse(
        '$projectUrl/rest/v1/objects?select=name,bucket_id&limit=50',
      );
      final storageHeaders = {
        ...headers,
        'accept-profile': 'storage',
      };

      final response = await http.get(url, headers: storageHeaders).timeout(
            const Duration(seconds: 10),
          );

      if (response.statusCode == 200) {
        final List<dynamic> data = jsonDecode(response.body);
        for (final obj in data) {
          final name = obj['name'] as String?;
          final bucketId = obj['bucket_id'] as String?;
          if (name != null) {
            objects.add(bucketId != null ? '$bucketId/$name' : name);
          }
        }
      }
    } catch (e) {
      // Storage objects query failed
    }

    return objects;
  }

  static Future<List<ExposedTableInfo>> _checkExposedTables(
    String projectUrl,
    Map<String, String> headers,
  ) async {
    final exposedTables = <ExposedTableInfo>[];
    final checkedTables = <String>{};

    // First, try to discover tables from PostgREST OpenAPI schema
    final discoveredTables = await _discoverTablesFromSchema(projectUrl, headers);

    // Combine discovered tables with common table names
    final allTablesToCheck = <String>{
      ...discoveredTables,
      ..._commonTableNames,
    };

    // Try each table name
    for (final tableName in allTablesToCheck) {
      if (checkedTables.contains(tableName)) continue;
      checkedTables.add(tableName);

      try {
        final url = Uri.parse(
          '$projectUrl/rest/v1/$tableName?select=*&limit=5',
        );

        final response = await http.get(url, headers: headers).timeout(
              const Duration(seconds: 5),
            );

        if (response.statusCode == 200) {
          final List<dynamic> data = jsonDecode(response.body);
          if (data.isNotEmpty) {
            final firstRow = data.first as Map<String, dynamic>;
            exposedTables.add(ExposedTableInfo(
              tableName: tableName,
              rowCount: data.length,
              columns: firstRow.keys.toList(),
              sampleData: data
                  .take(3)
                  .map((e) => Map<String, dynamic>.from(e))
                  .toList(),
            ));
          }
        }
      } catch (e) {
        // Table not accessible or doesn't exist
      }
    }

    return exposedTables;
  }

  /// Discovers available tables from PostgREST OpenAPI schema endpoint
  static Future<List<String>> _discoverTablesFromSchema(
    String projectUrl,
    Map<String, String> headers,
  ) async {
    final tables = <String>[];

    try {
      // PostgREST exposes an OpenAPI schema at the root
      final url = Uri.parse('$projectUrl/rest/v1/');
      final response = await http.get(url, headers: headers).timeout(
            const Duration(seconds: 10),
          );

      if (response.statusCode == 200) {
        final dynamic data = jsonDecode(response.body);

        // OpenAPI 3.0 format - paths contain table endpoints
        if (data is Map && data.containsKey('paths')) {
          final paths = data['paths'] as Map<String, dynamic>;
          for (final path in paths.keys) {
            // Extract table name from path like "/tablename"
            if (path.startsWith('/') && !path.contains('{')) {
              final tableName = path.substring(1);
              if (tableName.isNotEmpty && !tableName.contains('/')) {
                tables.add(tableName);
              }
            }
          }
        }

        // Try definitions/components schemas
        if (data is Map && data.containsKey('definitions')) {
          final definitions = data['definitions'] as Map<String, dynamic>;
          tables.addAll(definitions.keys.where((k) => !k.startsWith('_')));
        }

        if (data is Map && data.containsKey('components')) {
          final components = data['components'] as Map<String, dynamic>?;
          final schemas = components?['schemas'] as Map<String, dynamic>?;
          if (schemas != null) {
            tables.addAll(schemas.keys.where((k) => !k.startsWith('_')));
          }
        }
      }
    } catch (e) {
      // Schema discovery failed - fall back to common names
    }

    return tables;
  }

  static Future<SupabaseSecurityResult> checkMultipleCombinations({
    required List<String> projectUrls,
    required List<String> anonKeys,
  }) async {
    for (final projectUrl in projectUrls) {
      for (final anonKey in anonKeys) {
        final result = await checkSecurity(
          projectUrl: projectUrl,
          anonKey: anonKey,
        );

        if (result.isVulnerable) {
          return result;
        }
      }
    }

    return SupabaseSecurityResult.secure();
  }

  static String _normalizeProjectUrl(String url) {
    var normalized = url.trim();

    // Remove trailing slash
    if (normalized.endsWith('/')) {
      normalized = normalized.substring(0, normalized.length - 1);
    }

    // Ensure https
    if (!normalized.startsWith('http')) {
      normalized = 'https://$normalized';
    }

    return normalized;
  }
}
