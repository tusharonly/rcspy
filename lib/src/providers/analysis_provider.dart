import 'package:device_packages/device_packages.dart';
import 'package:flutter/foundation.dart';
import 'package:rcspy/src/services/apk_analyzer.dart';
import 'package:rcspy/src/services/remote_config_service.dart';
import 'package:rcspy/src/services/settings_service.dart';
import 'package:rcspy/src/services/storage_service.dart';
import 'package:rcspy/src/services/supabase_service.dart';

class AppAnalysisState {
  final ApkAnalysisResult? apkResult;
  final RemoteConfigResult? rcResult;
  final SupabaseSecurityResult? supabaseResult;
  final bool isAnalyzingApk;
  final bool isCheckingRc;
  final bool isCheckingSupabase;

  const AppAnalysisState({
    this.apkResult,
    this.rcResult,
    this.supabaseResult,
    this.isAnalyzingApk = false,
    this.isCheckingRc = false,
    this.isCheckingSupabase = false,
  });

  bool get hasFirebase => apkResult?.firebase.hasFirebase == true;
  bool get hasSupabase => apkResult?.supabase.hasSupabase == true;
  bool get hasAnyBackend => hasFirebase || hasSupabase;

  /// Returns true only if RC is accessible AND has values (respects settings)
  bool get isFirebaseVulnerable {
    if (rcResult == null || !rcResult!.isAccessible) return false;
    return SettingsService.isReallyVulnerable(
      isAccessible: rcResult!.isAccessible,
      configValueCount: rcResult!.configValues?.length ?? 0,
    );
  }

  /// Returns true if RC is accessible but empty (for display purposes)
  bool get isFirebaseAccessibleButEmpty {
    if (rcResult == null || !rcResult!.isAccessible) return false;
    return (rcResult!.configValues?.length ?? 0) == 0;
  }

  bool get isSupabaseVulnerable => supabaseResult?.isVulnerable == true;
  bool get isVulnerable => isFirebaseVulnerable || isSupabaseVulnerable;

  AppAnalysisState copyWith({
    ApkAnalysisResult? apkResult,
    RemoteConfigResult? rcResult,
    SupabaseSecurityResult? supabaseResult,
    bool? isAnalyzingApk,
    bool? isCheckingRc,
    bool? isCheckingSupabase,
  }) {
    return AppAnalysisState(
      apkResult: apkResult ?? this.apkResult,
      rcResult: rcResult ?? this.rcResult,
      supabaseResult: supabaseResult ?? this.supabaseResult,
      isAnalyzingApk: isAnalyzingApk ?? this.isAnalyzingApk,
      isCheckingRc: isCheckingRc ?? this.isCheckingRc,
      isCheckingSupabase: isCheckingSupabase ?? this.isCheckingSupabase,
    );
  }
}

class AnalysisProgress {
  final int total;
  final int completed;
  final int withFirebase;
  final int withSupabase;
  final int vulnerable;
  final int firebaseVulnerable;
  final int supabaseVulnerable;
  final int cached;
  final bool isComplete;

  const AnalysisProgress({
    this.total = 0,
    this.completed = 0,
    this.withFirebase = 0,
    this.withSupabase = 0,
    this.vulnerable = 0,
    this.firebaseVulnerable = 0,
    this.supabaseVulnerable = 0,
    this.cached = 0,
    this.isComplete = false,
  });

  double get progress => total > 0 ? completed / total : 0;
  int get remaining => total - completed;
  int get withAnyBackend => withFirebase + withSupabase;
}

enum AppFilter {
  all,
  vulnerable,
  firebase,
  supabase,
  firebaseVulnerable,
  supabaseVulnerable,
  secure,
  noBackend,
}

class AnalysisProvider extends ChangeNotifier {
  static const int _maxParallelAnalysis = 4;

  List<PackageInfo> _packages = [];
  final Map<String, AppAnalysisState> _analysisStates = {};
  AnalysisProgress _progress = const AnalysisProgress();
  bool _isLoadingPackages = true;
  bool _isAnalyzing = false;
  bool _hasStartedScan = false;
  int _newAppsCount = 0;
  AppFilter _currentFilter = AppFilter.all;
  String _searchQuery = '';

  List<PackageInfo> get packages => _packages;
  AnalysisProgress get progress => _progress;
  bool get isLoadingPackages => _isLoadingPackages;
  bool get isAnalyzing => _isAnalyzing;
  bool get hasStartedScan => _hasStartedScan;
  String get searchQuery => _searchQuery;
  int get newAppsCount => _newAppsCount;
  AppFilter get currentFilter => _currentFilter;

  List<PackageInfo> get filteredPackages {
    var result = _packages;

    // Apply search filter first
    if (_searchQuery.isNotEmpty) {
      final query = _searchQuery.toLowerCase();
      result = result.where((package) {
        final name = (package.name ?? '').toLowerCase();
        final id = (package.id ?? '').toLowerCase();
        return name.contains(query) || id.contains(query);
      }).toList();
    }

    // Then apply category filter
    if (_currentFilter == AppFilter.all) {
      return result;
    }

    return result.where((package) {
      final packageId = _getPackageId(package);
      final state = _analysisStates[packageId];

      if (state == null) return false;

      switch (_currentFilter) {
        case AppFilter.all:
          return true;
        case AppFilter.vulnerable:
          return state.isVulnerable;
        case AppFilter.firebase:
          return state.hasFirebase;
        case AppFilter.supabase:
          return state.hasSupabase;
        case AppFilter.firebaseVulnerable:
          return state.isFirebaseVulnerable;
        case AppFilter.supabaseVulnerable:
          return state.isSupabaseVulnerable;
        case AppFilter.secure:
          return state.hasAnyBackend && !state.isVulnerable;
        case AppFilter.noBackend:
          return !state.hasAnyBackend && state.apkResult?.error == null;
      }
    }).toList();
  }

  void setSearchQuery(String query) {
    if (_searchQuery != query) {
      _searchQuery = query;
      notifyListeners();
    }
  }

  void setFilter(AppFilter filter) {
    if (_currentFilter != filter) {
      _currentFilter = filter;
      notifyListeners();
    }
  }

  AppAnalysisState? getState(String packageId) => _analysisStates[packageId];

  Future<void> loadPackages() async {
    _isLoadingPackages = true;
    notifyListeners();

    await StorageService.init();
    await SettingsService.init();

    final cachedData = StorageService.loadCache();
    int cachedFirebase = 0;
    int cachedSupabase = 0;
    int cachedVulnerable = 0;
    int cachedFirebaseVulnerable = 0;
    int cachedSupabaseVulnerable = 0;

    for (final entry in cachedData.entries) {
      final data = entry.value;
      _analysisStates[entry.key] = AppAnalysisState(
        apkResult: data.toApkResult(),
        rcResult: data.toRcResult(),
        supabaseResult: data.toSupabaseSecurityResult(),
      );
      if (data.hasFirebase) cachedFirebase++;
      if (data.hasSupabase) cachedSupabase++;

      // Check if Firebase RC is really vulnerable (respects settings)
      final rcConfigCount = data.rcConfigValues?.length ?? 0;
      if (data.rcAccessible == true &&
          SettingsService.isReallyVulnerable(
            isAccessible: true,
            configValueCount: rcConfigCount,
          )) {
        cachedVulnerable++;
        cachedFirebaseVulnerable++;
      }

      if (data.supabaseVulnerable == true) {
        cachedVulnerable++;
        cachedSupabaseVulnerable++;
      }
    }

    _packages = await DevicePackages.getInstalledPackages(
      includeIcon: true,
      includeSystemPackages: false,
    );

    _packages.sort((a, b) {
      final nameA = (a.name ?? a.id ?? '').toLowerCase();
      final nameB = (b.name ?? b.id ?? '').toLowerCase();
      return nameA.compareTo(nameB);
    });

    final analyzedIds = StorageService.getAnalyzedPackageIds();
    final newApps = _packages.where((p) {
      final id = _getPackageId(p);
      return !analyzedIds.contains(id);
    }).toList();

    _newAppsCount = newApps.length;

    _isLoadingPackages = false;

    _progress = AnalysisProgress(
      total: _packages.length,
      completed: _packages.length - newApps.length,
      withFirebase: cachedFirebase,
      withSupabase: cachedSupabase,
      vulnerable: cachedVulnerable,
      firebaseVulnerable: cachedFirebaseVulnerable,
      supabaseVulnerable: cachedSupabaseVulnerable,
      cached: cachedData.length,
      isComplete: newApps.isEmpty,
    );

    notifyListeners();
    // Don't auto-scan - wait for user to press scan button
  }

  /// Start scanning apps that haven't been analyzed yet
  Future<void> startScan() async {
    if (_isAnalyzing) return;

    _hasStartedScan = true;
    notifyListeners();

    final analyzedIds = StorageService.getAnalyzedPackageIds();
    final newApps = _packages.where((p) {
      final id = _getPackageId(p);
      return !analyzedIds.contains(id);
    }).toList();

    if (newApps.isNotEmpty) {
      await _analyzePackages(newApps, isFullReanalysis: false);
    }
  }

  Future<void> reanalyzeAll() async {
    if (_isAnalyzing) return;

    await StorageService.clearCache();
    _analysisStates.clear();

    await _analyzePackages(_packages, isFullReanalysis: true);
  }

  Future<void> reanalyzePackage(PackageInfo package) async {
    final packageId = _getPackageId(package);

    await StorageService.removeAppData(packageId);

    _analysisStates[packageId] = const AppAnalysisState(isAnalyzingApk: true);
    notifyListeners();

    await _analyzePackage(package, saveToCache: true);

    _updateProgressStats();
    notifyListeners();
  }

  Future<void> _analyzePackages(
    List<PackageInfo> packagesToAnalyze, {
    required bool isFullReanalysis,
  }) async {
    if (packagesToAnalyze.isEmpty) return;

    _isAnalyzing = true;

    int completed = isFullReanalysis ? 0 : _progress.completed;
    int withFirebase = isFullReanalysis ? 0 : _progress.withFirebase;
    int withSupabase = isFullReanalysis ? 0 : _progress.withSupabase;
    int vulnerable = isFullReanalysis ? 0 : _progress.vulnerable;
    int firebaseVulnerable = isFullReanalysis ? 0 : _progress.firebaseVulnerable;
    int supabaseVulnerable = isFullReanalysis ? 0 : _progress.supabaseVulnerable;

    _progress = AnalysisProgress(
      total: _packages.length,
      completed: completed,
      withFirebase: withFirebase,
      withSupabase: withSupabase,
      vulnerable: vulnerable,
      firebaseVulnerable: firebaseVulnerable,
      supabaseVulnerable: supabaseVulnerable,
    );
    notifyListeners();

    final batches = _createBatches(packagesToAnalyze, _maxParallelAnalysis);

    for (final batch in batches) {
      for (final package in batch) {
        final packageId = _getPackageId(package);
        _analysisStates[packageId] = const AppAnalysisState(
          isAnalyzingApk: true,
        );
      }
      notifyListeners();

      final futures = batch
          .map((p) => _analyzePackage(p, saveToCache: true))
          .toList();
      final results = await Future.wait(futures);

      for (final result in results) {
        completed++;
        if (result.hasFirebase) withFirebase++;
        if (result.hasSupabase) withSupabase++;
        if (result.isFirebaseVulnerable) {
          vulnerable++;
          firebaseVulnerable++;
        }
        if (result.isSupabaseVulnerable) {
          vulnerable++;
          supabaseVulnerable++;
        }
      }

      _progress = AnalysisProgress(
        total: _packages.length,
        completed: completed,
        withFirebase: withFirebase,
        withSupabase: withSupabase,
        vulnerable: vulnerable,
        firebaseVulnerable: firebaseVulnerable,
        supabaseVulnerable: supabaseVulnerable,
      );
      notifyListeners();
    }

    _isAnalyzing = false;
    _newAppsCount = 0;
    _progress = AnalysisProgress(
      total: _packages.length,
      completed: completed,
      withFirebase: withFirebase,
      withSupabase: withSupabase,
      vulnerable: vulnerable,
      firebaseVulnerable: firebaseVulnerable,
      supabaseVulnerable: supabaseVulnerable,
      isComplete: true,
    );
    notifyListeners();
  }

  Future<
      ({
        bool hasFirebase,
        bool hasSupabase,
        bool isFirebaseVulnerable,
        bool isSupabaseVulnerable,
      })> _analyzePackage(
    PackageInfo package, {
    bool saveToCache = false,
  }) async {
    final packageId = _getPackageId(package);
    final apkPath = package.installerPath;

    if (apkPath == null || apkPath.isEmpty) {
      _analysisStates[packageId] = AppAnalysisState(
        apkResult: ApkAnalysisResult.error('No APK path'),
        isAnalyzingApk: false,
      );
      if (saveToCache) {
        await StorageService.saveAppData(
          CachedAppData(
            packageId: packageId,
            hasFirebase: false,
            error: 'No APK path',
            analyzedAt: DateTime.now(),
          ),
        );
      }
      return (
        hasFirebase: false,
        hasSupabase: false,
        isFirebaseVulnerable: false,
        isSupabaseVulnerable: false,
      );
    }

    try {
      final apkResult = await ApkAnalyzer.analyzeApk(apkPath);

      bool isFirebaseVulnerable = false;
      bool isSupabaseVulnerable = false;
      RemoteConfigResult? rcResult;
      SupabaseSecurityResult? supabaseResult;

      // Check Firebase Remote Config
      if (apkResult.firebase.hasFirebase &&
          apkResult.firebase.googleAppIds.isNotEmpty &&
          apkResult.firebase.googleApiKeys.isNotEmpty) {
        _analysisStates[packageId] = AppAnalysisState(
          apkResult: apkResult,
          isAnalyzingApk: false,
          isCheckingRc: true,
        );

        rcResult = await RemoteConfigService.checkMultipleCombinations(
          googleAppIds: apkResult.firebase.googleAppIds,
          apiKeys: apkResult.firebase.googleApiKeys,
        );

        isFirebaseVulnerable = rcResult.isAccessible;
      }

      // Check Supabase security
      if (apkResult.supabase.hasSupabase &&
          apkResult.supabase.projectUrls.isNotEmpty &&
          apkResult.supabase.anonKeys.isNotEmpty) {
        _analysisStates[packageId] = AppAnalysisState(
          apkResult: apkResult,
          rcResult: rcResult,
          isAnalyzingApk: false,
          isCheckingRc: false,
          isCheckingSupabase: true,
        );

        supabaseResult = await SupabaseService.checkMultipleCombinations(
          projectUrls: apkResult.supabase.projectUrls,
          anonKeys: apkResult.supabase.anonKeys,
        );

        isSupabaseVulnerable = supabaseResult.isVulnerable;
      }

      _analysisStates[packageId] = AppAnalysisState(
        apkResult: apkResult,
        rcResult: rcResult,
        supabaseResult: supabaseResult,
        isAnalyzingApk: false,
        isCheckingRc: false,
        isCheckingSupabase: false,
      );

      if (saveToCache) {
        await StorageService.saveAppData(
          CachedAppData(
            packageId: packageId,
            hasFirebase: apkResult.firebase.hasFirebase,
            googleAppIds: apkResult.firebase.googleAppIds,
            googleApiKeys: apkResult.firebase.googleApiKeys,
            rcAccessible: rcResult?.isAccessible,
            rcConfigValues: rcResult?.configValues,
            hasSupabase: apkResult.supabase.hasSupabase,
            supabaseUrls: apkResult.supabase.projectUrls,
            supabaseAnonKeys: apkResult.supabase.anonKeys,
            supabaseVulnerable: supabaseResult?.isVulnerable,
            supabaseSecurityData: supabaseResult?.toMap(),
            analyzedAt: DateTime.now(),
          ),
        );
      }

      return (
        hasFirebase: apkResult.firebase.hasFirebase,
        hasSupabase: apkResult.supabase.hasSupabase,
        isFirebaseVulnerable: isFirebaseVulnerable,
        isSupabaseVulnerable: isSupabaseVulnerable,
      );
    } catch (e) {
      _analysisStates[packageId] = AppAnalysisState(
        apkResult: ApkAnalysisResult.error(e.toString()),
        isAnalyzingApk: false,
      );
      if (saveToCache) {
        await StorageService.saveAppData(
          CachedAppData(
            packageId: packageId,
            hasFirebase: false,
            error: e.toString(),
            analyzedAt: DateTime.now(),
          ),
        );
      }
      return (
        hasFirebase: false,
        hasSupabase: false,
        isFirebaseVulnerable: false,
        isSupabaseVulnerable: false,
      );
    }
  }

  void _updateProgressStats() {
    int withFirebase = 0;
    int withSupabase = 0;
    int vulnerable = 0;
    int firebaseVulnerable = 0;
    int supabaseVulnerable = 0;

    for (final state in _analysisStates.values) {
      if (state.hasFirebase) withFirebase++;
      if (state.hasSupabase) withSupabase++;
      if (state.isFirebaseVulnerable) {
        vulnerable++;
        firebaseVulnerable++;
      }
      if (state.isSupabaseVulnerable) {
        vulnerable++;
        supabaseVulnerable++;
      }
    }

    _progress = AnalysisProgress(
      total: _packages.length,
      completed: _packages.length,
      withFirebase: withFirebase,
      withSupabase: withSupabase,
      vulnerable: vulnerable,
      firebaseVulnerable: firebaseVulnerable,
      supabaseVulnerable: supabaseVulnerable,
      isComplete: true,
    );
  }

  String _getPackageId(PackageInfo package) => package.id ?? package.name ?? '';

  List<List<PackageInfo>> _createBatches(
    List<PackageInfo> packages,
    int batchSize,
  ) {
    final batches = <List<PackageInfo>>[];
    for (var i = 0; i < packages.length; i += batchSize) {
      final end = (i + batchSize < packages.length)
          ? i + batchSize
          : packages.length;
      batches.add(packages.sublist(i, end));
    }
    return batches;
  }
}
