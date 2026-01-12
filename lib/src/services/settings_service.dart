import 'package:shared_preferences/shared_preferences.dart';

class SettingsService {
  static const String _hideEmptyRcKey = 'hide_empty_rc';
  static const String _minConfigValuesKey = 'min_config_values';

  static SharedPreferences? _prefs;

  static Future<void> init() async {
    _prefs ??= await SharedPreferences.getInstance();
  }

  /// Hide apps with accessible but empty Remote Config from "Vulnerable" filter
  static bool get hideEmptyRemoteConfig {
    return _prefs?.getBool(_hideEmptyRcKey) ?? true; // Default: hide empty RC
  }

  static Future<void> setHideEmptyRemoteConfig(bool value) async {
    await _prefs?.setBool(_hideEmptyRcKey, value);
  }

  /// Minimum number of config values to be considered "vulnerable"
  /// Default: 1 (at least one value must be exposed)
  static int get minConfigValuesToBeVulnerable {
    return _prefs?.getInt(_minConfigValuesKey) ?? 1;
  }

  static Future<void> setMinConfigValuesToBeVulnerable(int value) async {
    await _prefs?.setInt(_minConfigValuesKey, value);
  }

  /// Check if a Remote Config result should be considered vulnerable
  static bool isReallyVulnerable({
    required bool isAccessible,
    required int configValueCount,
  }) {
    if (!isAccessible) return false;
    if (hideEmptyRemoteConfig && configValueCount < minConfigValuesToBeVulnerable) {
      return false;
    }
    return true;
  }
}
