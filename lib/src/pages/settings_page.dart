import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:rcspy/src/services/settings_service.dart';
import 'package:rcspy/src/services/storage_service.dart';
import 'package:url_launcher/url_launcher.dart';

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  static const String _githubUrl = 'https://github.com/tusharonly/rcspy';
  String _version = '';
  bool _hideEmptyRc = true;

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    await SettingsService.init();
    final packageInfo = await PackageInfo.fromPlatform();
    setState(() {
      _version = 'v${packageInfo.version} (${packageInfo.buildNumber})';
      _hideEmptyRc = SettingsService.hideEmptyRemoteConfig;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          const SizedBox(height: 8),

          _SectionHeader(title: 'Analysis Settings'),
          SwitchListTile(
            secondary: Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.orange.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.filter_alt, color: Colors.orange, size: 20),
            ),
            title: const Text(
              'Hide Empty Remote Config',
              style: TextStyle(fontWeight: FontWeight.w500, fontSize: 15),
            ),
            subtitle: Text(
              'Don\'t count apps with accessible but empty Remote Config as vulnerable',
              style: TextStyle(fontSize: 13, color: Colors.grey[600]),
            ),
            value: _hideEmptyRc,
            onChanged: (value) async {
              await SettingsService.setHideEmptyRemoteConfig(value);
              setState(() => _hideEmptyRc = value);
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(
                      value
                          ? 'Empty Remote Config will be hidden from Vulnerable filter'
                          : 'All accessible Remote Config will be shown as Vulnerable',
                    ),
                    duration: const Duration(seconds: 2),
                  ),
                );
              }
            },
          ),

          const Divider(height: 32),

          _SectionHeader(title: 'Links'),
          _SettingsTile(
            icon: Icons.code,
            title: 'Source Code',
            subtitle: 'View on GitHub',
            onTap: () => _launchUrl(_githubUrl),
            trailing: const Icon(Icons.open_in_new, size: 18),
          ),
          _SettingsTile(
            icon: Icons.bug_report_outlined,
            title: 'Report Issue',
            subtitle: 'Found a bug? Let us know',
            onTap: () => _launchUrl('$_githubUrl/issues'),
            trailing: const Icon(Icons.open_in_new, size: 18),
          ),
          _SettingsTile(
            icon: Icons.alternate_email,
            title: 'Follow on 𝕏',
            subtitle: '@tusharghige',
            onTap: () => _launchUrl('https://x.com/tusharghige'),
            trailing: const Icon(Icons.open_in_new, size: 18),
          ),

          const Divider(height: 32),

          _SectionHeader(title: 'Data'),
          _SettingsTile(
            icon: Icons.delete_outline,
            title: 'Clear Cache',
            subtitle: 'Remove all saved analysis results',
            onTap: () => _showClearCacheDialog(context),
          ),

          const Divider(height: 32),

          _SectionHeader(title: 'How It Works'),
          _InfoTile(
            icon: Icons.help_outline,
            title: 'What does this app do?',
            content: '''
RC Spy scans installed Android apps to find security misconfigurations in Firebase and Supabase backends.

**Firebase Remote Config**
- Extracts Google App IDs and API Keys from APK files
- Tests if Remote Config endpoints are publicly accessible
- Shows exposed configuration values that could leak secrets

**Supabase**
- Finds Supabase project URLs and anon keys in APKs
- Checks for publicly accessible storage buckets
- Tests common database tables for exposed data

**Why does this matter?**
Misconfigured backends can expose:
- API keys and secrets
- Feature flags
- Server URLs
- User data (in Supabase tables)
- Files (in public storage buckets)

Security researchers can use this to identify vulnerable apps and responsibly disclose issues to developers.
''',
          ),

          const SizedBox(height: 32),

          Center(
            child: Text(
              'Made with ❤️ for security researchers',
              style: TextStyle(
                color: Colors.grey[500],
                fontSize: 12,
              ),
            ),
          ),
          const SizedBox(height: 8),
          Center(
            child: Text(
              _version,
              style: TextStyle(
                color: Colors.grey[400],
                fontSize: 11,
              ),
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Future<void> _launchUrl(String url) async {
    final uri = Uri.parse(url);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  void _showClearCacheDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear Cache'),
        content: const Text(
          'This will remove all saved analysis results. '
          'Apps will be re-analyzed on next launch.\n\n'
          'Continue?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () async {
              await StorageService.clearCache();
              if (context.mounted) {
                Navigator.pop(context);
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Cache cleared successfully'),
                    duration: Duration(seconds: 2),
                  ),
                );
              }
            },
            child: const Text('Clear'),
          ),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader({required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
      child: Text(
        title.toUpperCase(),
        style: TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w600,
          color: Colors.grey[600],
          letterSpacing: 0.5,
        ),
      ),
    );
  }
}

class _SettingsTile extends StatelessWidget {
  const _SettingsTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    this.onTap,
    this.trailing,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback? onTap;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: Colors.blue.withOpacity(0.1),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Icon(icon, color: Colors.blue, size: 20),
      ),
      title: Text(
        title,
        style: const TextStyle(
          fontWeight: FontWeight.w500,
          fontSize: 15,
        ),
      ),
      subtitle: Text(
        subtitle,
        style: TextStyle(
          fontSize: 13,
          color: Colors.grey[600],
        ),
      ),
      trailing: trailing,
      onTap: onTap,
    );
  }
}

class _InfoTile extends StatelessWidget {
  const _InfoTile({
    required this.icon,
    required this.title,
    required this.content,
  });

  final IconData icon;
  final String title;
  final String content;

  @override
  Widget build(BuildContext context) {
    return ExpansionTile(
      leading: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: Colors.purple.withOpacity(0.1),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Icon(icon, color: Colors.purple, size: 20),
      ),
      title: Text(
        title,
        style: const TextStyle(
          fontWeight: FontWeight.w500,
          fontSize: 15,
        ),
      ),
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.grey[50],
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.grey[200]!),
            ),
            child: Text(
              content.trim(),
              style: TextStyle(
                fontSize: 13,
                color: Colors.grey[700],
                height: 1.5,
              ),
            ),
          ),
        ),
      ],
    );
  }
}
