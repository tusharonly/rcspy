import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:rcspy/src/services/supabase_service.dart';
import 'package:share_plus/share_plus.dart';

enum SupabaseViewMode { overview, list, table, json }

class SupabaseResultsPage extends StatefulWidget {
  const SupabaseResultsPage({
    super.key,
    required this.appName,
    required this.result,
  });

  final String appName;
  final SupabaseSecurityResult result;

  @override
  State<SupabaseResultsPage> createState() => _SupabaseResultsPageState();
}

class _SupabaseResultsPageState extends State<SupabaseResultsPage> {
  SupabaseViewMode _viewMode = SupabaseViewMode.overview;

  int get _totalIssues =>
      widget.result.publicBuckets.length +
      widget.result.exposedTables.length +
      widget.result.exposedStorageObjects.length;

  List<_FindingItem> get _findings {
    final items = <_FindingItem>[];

    // Add project URL as first item
    if (widget.result.workingProjectUrl != null) {
      items.add(_FindingItem(
        type: _FindingType.info,
        title: 'Project URL',
        value: widget.result.workingProjectUrl!,
        icon: Icons.link,
        color: Colors.teal,
      ));
    }

    // Add API key
    if (widget.result.workingAnonKey != null) {
      items.add(_FindingItem(
        type: _FindingType.info,
        title: 'Anon Key',
        value: widget.result.workingAnonKey!,
        icon: Icons.key,
        color: Colors.indigo,
      ));
    }

    // Add exposed tables
    for (final table in widget.result.exposedTables) {
      items.add(_FindingItem(
        type: _FindingType.table,
        title: table.tableName,
        value: table.sampleData.isNotEmpty
            ? const JsonEncoder.withIndent('  ').convert(table.sampleData)
            : 'Columns: ${table.columns.join(', ')}',
        icon: Icons.table_chart,
        color: Colors.purple,
        metadata: {
          'columns': table.columns,
          'rowCount': table.rowCount,
          'sampleData': table.sampleData,
        },
      ));
    }

    // Add public buckets
    for (final bucket in widget.result.publicBuckets) {
      items.add(_FindingItem(
        type: _FindingType.bucket,
        title: bucket.name,
        value: bucket.isPublic ? 'Public Access Enabled' : 'Private',
        icon: Icons.folder_open,
        color: Colors.orange,
        metadata: {
          'id': bucket.id,
          'isPublic': bucket.isPublic,
          'exposedFiles': bucket.exposedFiles,
        },
      ));
    }

    // Add exposed storage objects
    for (final object in widget.result.exposedStorageObjects) {
      items.add(_FindingItem(
        type: _FindingType.file,
        title: object.split('/').last,
        value: object,
        icon: Icons.insert_drive_file,
        color: Colors.blue,
      ));
    }

    return items;
  }

  Map<String, dynamic> get _jsonData => {
        'projectUrl': widget.result.workingProjectUrl,
        'anonKey': widget.result.workingAnonKey,
        'isVulnerable': widget.result.isVulnerable,
        'summary': {
          'publicBuckets': widget.result.publicBuckets.length,
          'exposedTables': widget.result.exposedTables.length,
          'exposedStorageObjects': widget.result.exposedStorageObjects.length,
        },
        'publicBuckets':
            widget.result.publicBuckets.map((b) => b.toMap()).toList(),
        'exposedTables':
            widget.result.exposedTables.map((t) => t.toMap()).toList(),
        'exposedStorageObjects': widget.result.exposedStorageObjects,
      };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.appName,
              style: const TextStyle(fontSize: 16),
            ),
            Text(
              '$_totalIssues security issues found',
              style: TextStyle(
                fontSize: 12,
                color: _totalIssues > 0 ? Colors.red[400] : Colors.green[400],
                fontWeight: FontWeight.normal,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.share),
            tooltip: 'Share for analysis',
            onPressed: () => _shareForAnalysis(context),
          ),
          IconButton(
            icon: const Icon(Icons.copy_all),
            tooltip: 'Copy all as JSON',
            onPressed: () => _copyAllAsJson(context),
          ),
        ],
      ),
      body: _totalIssues == 0
          ? const _EmptyState()
          : Column(
              children: [
                _ViewModeSwitcher(
                  currentMode: _viewMode,
                  onModeChanged: (mode) => setState(() => _viewMode = mode),
                  result: widget.result,
                ),
                Expanded(child: _buildContent()),
              ],
            ),
    );
  }

  Widget _buildContent() {
    switch (_viewMode) {
      case SupabaseViewMode.overview:
        return _OverviewView(result: widget.result);
      case SupabaseViewMode.list:
        return _ListView(findings: _findings);
      case SupabaseViewMode.table:
        return _DataTableView(findings: _findings);
      case SupabaseViewMode.json:
        return _JsonView(jsonData: _jsonData);
    }
  }

  void _copyAllAsJson(BuildContext context) {
    final jsonString = const JsonEncoder.withIndent('  ').convert(_jsonData);
    Clipboard.setData(ClipboardData(text: jsonString));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Copied all results to clipboard'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  void _shareForAnalysis(BuildContext context) {
    final bucketNames =
        widget.result.publicBuckets.map((b) => b.name).join(', ');
    final tableNames =
        widget.result.exposedTables.map((t) => t.tableName).join(', ');

    final jsonString = const JsonEncoder.withIndent('  ').convert(_jsonData);

    final shareText = '''
Supabase Security Analysis Report
==================================
App: ${widget.appName}
Project URL: ${widget.result.workingProjectUrl ?? 'Unknown'}
Anon Key: ${widget.result.workingAnonKey ?? 'Unknown'}

**Security Issues Found:**
- Public Storage Buckets: ${widget.result.publicBuckets.length}${bucketNames.isNotEmpty ? ' ($bucketNames)' : ''}
- Exposed Database Tables: ${widget.result.exposedTables.length}${tableNames.isNotEmpty ? ' ($tableNames)' : ''}
- Exposed Storage Files: ${widget.result.exposedStorageObjects.length}

**Full Details:**
$jsonString

**Analysis Request:**
Please analyze these Supabase security findings and identify:
1. What sensitive data might be exposed through these misconfigurations
2. Potential attack vectors using the exposed endpoints
3. Security risks from public storage buckets and database tables
4. Row Level Security (RLS) recommendations
5. Steps the developer should take to secure this backend

---
Generated by RC Spy - Security Research Tool
''';

    Share.share(shareText, subject: 'RC Spy: ${widget.appName} Supabase Analysis');
  }
}

enum _FindingType { info, table, bucket, file }

class _FindingItem {
  final _FindingType type;
  final String title;
  final String value;
  final IconData icon;
  final Color color;
  final Map<String, dynamic>? metadata;

  _FindingItem({
    required this.type,
    required this.title,
    required this.value,
    required this.icon,
    required this.color,
    this.metadata,
  });

  String get typeLabel {
    switch (type) {
      case _FindingType.info:
        return 'INFO';
      case _FindingType.table:
        return 'TABLE';
      case _FindingType.bucket:
        return 'BUCKET';
      case _FindingType.file:
        return 'FILE';
    }
  }
}

class _ViewModeSwitcher extends StatelessWidget {
  const _ViewModeSwitcher({
    required this.currentMode,
    required this.onModeChanged,
    required this.result,
  });

  final SupabaseViewMode currentMode;
  final ValueChanged<SupabaseViewMode> onModeChanged;
  final SupabaseSecurityResult result;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      child: SegmentedButton<SupabaseViewMode>(
        segments: const [
          ButtonSegment(
            value: SupabaseViewMode.overview,
            icon: Icon(Icons.dashboard, size: 18),
            label: Text('Overview'),
          ),
          ButtonSegment(
            value: SupabaseViewMode.list,
            icon: Icon(Icons.view_list, size: 18),
            label: Text('List'),
          ),
          ButtonSegment(
            value: SupabaseViewMode.table,
            icon: Icon(Icons.table_chart, size: 18),
            label: Text('Table'),
          ),
          ButtonSegment(
            value: SupabaseViewMode.json,
            icon: Icon(Icons.data_object, size: 18),
            label: Text('JSON'),
          ),
        ],
        selected: {currentMode},
        onSelectionChanged: (selected) => onModeChanged(selected.first),
        showSelectedIcon: false,
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.check_circle, size: 64, color: Colors.green),
          SizedBox(height: 16),
          Text(
            'No vulnerabilities detected\nin Supabase configuration',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 16, color: Colors.grey),
          ),
        ],
      ),
    );
  }
}

// ============================================
// OVERVIEW VIEW - Category-based display
// ============================================

class _OverviewView extends StatelessWidget {
  const _OverviewView({required this.result});

  final SupabaseSecurityResult result;

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Credentials Section
        _SectionHeader(
          icon: Icons.vpn_key,
          title: 'Credentials',
          color: Colors.teal,
        ),
        const SizedBox(height: 12),
        if (result.workingProjectUrl != null)
          _CredentialCard(
            label: 'Project URL',
            value: result.workingProjectUrl!,
            icon: Icons.link,
            color: Colors.teal,
          ),
        if (result.workingAnonKey != null) ...[
          const SizedBox(height: 8),
          _CredentialCard(
            label: 'Anon Key',
            value: result.workingAnonKey!,
            icon: Icons.key,
            color: Colors.indigo,
          ),
        ],
        const SizedBox(height: 24),

        // Summary Stats
        _SectionHeader(
          icon: Icons.warning_amber,
          title: 'Security Issues Summary',
          color: Colors.red,
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: _StatCard(
                icon: Icons.table_chart,
                label: 'Exposed Tables',
                count: result.exposedTables.length,
                color: Colors.purple,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _StatCard(
                icon: Icons.folder_open,
                label: 'Public Buckets',
                count: result.publicBuckets.length,
                color: Colors.orange,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: _StatCard(
                icon: Icons.insert_drive_file,
                label: 'Exposed Files',
                count: result.exposedStorageObjects.length,
                color: Colors.blue,
              ),
            ),
            const Expanded(child: SizedBox()),
          ],
        ),
        const SizedBox(height: 24),

        // Exposed Tables
        if (result.exposedTables.isNotEmpty) ...[
          _SectionHeader(
            icon: Icons.table_chart,
            title: 'Exposed Database Tables',
            color: Colors.purple,
          ),
          const SizedBox(height: 12),
          ...result.exposedTables.map((table) => _TableCard(table: table)),
          const SizedBox(height: 24),
        ],

        // Public Buckets
        if (result.publicBuckets.isNotEmpty) ...[
          _SectionHeader(
            icon: Icons.folder_open,
            title: 'Public Storage Buckets',
            color: Colors.orange,
          ),
          const SizedBox(height: 12),
          ...result.publicBuckets.map((bucket) => _BucketCard(bucket: bucket)),
          const SizedBox(height: 24),
        ],

        // Exposed Files
        if (result.exposedStorageObjects.isNotEmpty) ...[
          _SectionHeader(
            icon: Icons.insert_drive_file,
            title: 'Exposed Storage Files',
            color: Colors.blue,
          ),
          const SizedBox(height: 12),
          ...result.exposedStorageObjects.map((obj) => _FileCard(path: obj)),
        ],
      ],
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader({
    required this.icon,
    required this.title,
    required this.color,
  });

  final IconData icon;
  final String title;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: color.withOpacity(0.1),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(icon, size: 20, color: color),
        ),
        const SizedBox(width: 12),
        Text(
          title,
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: Colors.grey[800],
          ),
        ),
      ],
    );
  }
}

class _CredentialCard extends StatelessWidget {
  const _CredentialCard({
    required this.label,
    required this.value,
    required this.icon,
    required this.color,
  });

  final String label;
  final String value;
  final IconData icon;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: color.withOpacity(0.05),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () {
            Clipboard.setData(ClipboardData(text: value));
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('$label copied to clipboard'),
                duration: const Duration(seconds: 1),
              ),
            );
          },
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: color.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(icon, size: 20, color: color),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        label,
                        style: TextStyle(
                          fontSize: 12,
                          color: Colors.grey[600],
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        value,
                        style: TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 13,
                          color: color,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                Icon(Icons.copy, size: 20, color: color.withOpacity(0.5)),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _StatCard extends StatelessWidget {
  const _StatCard({
    required this.icon,
    required this.label,
    required this.count,
    required this.color,
  });

  final IconData icon;
  final String label;
  final int count;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: count > 0 ? color.withOpacity(0.1) : Colors.grey[100],
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: count > 0 ? color.withOpacity(0.3) : Colors.grey[300]!,
        ),
      ),
      child: Column(
        children: [
          Icon(icon, size: 32, color: count > 0 ? color : Colors.grey),
          const SizedBox(height: 8),
          Text(
            '$count',
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.bold,
              color: count > 0 ? color : Colors.grey,
            ),
          ),
          Text(
            label,
            style: TextStyle(fontSize: 12, color: Colors.grey[600]),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}

class _TableCard extends StatefulWidget {
  const _TableCard({required this.table});

  final ExposedTableInfo table;

  @override
  State<_TableCard> createState() => _TableCardState();
}

class _TableCardState extends State<_TableCard> {
  bool _isExpanded = false;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.purple.withOpacity(0.2)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.03),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: Colors.purple.withOpacity(0.05),
              borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
            ),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(
                    color: Colors.purple.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: const Icon(Icons.table_chart, size: 16, color: Colors.purple),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        widget.table.tableName,
                        style: TextStyle(
                          fontWeight: FontWeight.w600,
                          fontSize: 14,
                          color: Colors.grey.shade800,
                        ),
                      ),
                      Text(
                        '${widget.table.columns.length} columns • ${widget.table.rowCount ?? 0} rows',
                        style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                      ),
                    ],
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Colors.red.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: const Text(
                    'EXPOSED',
                    style: TextStyle(
                      color: Colors.red,
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
          ),

          // Columns
          Padding(
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Columns:',
                  style: TextStyle(
                    fontWeight: FontWeight.w600,
                    fontSize: 12,
                    color: Colors.grey[700],
                  ),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 6,
                  runSpacing: 6,
                  children: widget.table.columns.map((col) => Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: Colors.grey[100],
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      col,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                    ),
                  )).toList(),
                ),
              ],
            ),
          ),

          // Sample Data (Expandable)
          if (widget.table.sampleData.isNotEmpty) ...[
            const Divider(height: 1),
            InkWell(
              onTap: () => setState(() => _isExpanded = !_isExpanded),
              child: Padding(
                padding: const EdgeInsets.all(14),
                child: Row(
                  children: [
                    Icon(
                      _isExpanded ? Icons.expand_less : Icons.expand_more,
                      size: 20,
                      color: Colors.purple,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      _isExpanded ? 'Hide Sample Data' : 'Show Sample Data',
                      style: const TextStyle(
                        color: Colors.purple,
                        fontWeight: FontWeight.w600,
                        fontSize: 13,
                      ),
                    ),
                    const Spacer(),
                    if (!_isExpanded)
                      IconButton(
                        icon: const Icon(Icons.copy, size: 18),
                        color: Colors.purple,
                        onPressed: () {
                          final json = const JsonEncoder.withIndent('  ')
                              .convert(widget.table.sampleData);
                          Clipboard.setData(ClipboardData(text: json));
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Sample data copied'),
                              duration: Duration(seconds: 1),
                            ),
                          );
                        },
                      ),
                  ],
                ),
              ),
            ),
            if (_isExpanded)
              Container(
                margin: const EdgeInsets.fromLTRB(14, 0, 14, 14),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E1E1E),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Stack(
                  children: [
                    SelectableText(
                      const JsonEncoder.withIndent('  ')
                          .convert(widget.table.sampleData),
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 11,
                        color: Color(0xFFD4D4D4),
                      ),
                    ),
                    Positioned(
                      top: 0,
                      right: 0,
                      child: IconButton(
                        icon: const Icon(Icons.copy, size: 16, color: Colors.white54),
                        onPressed: () {
                          final json = const JsonEncoder.withIndent('  ')
                              .convert(widget.table.sampleData);
                          Clipboard.setData(ClipboardData(text: json));
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Sample data copied'),
                              duration: Duration(seconds: 1),
                            ),
                          );
                        },
                      ),
                    ),
                  ],
                ),
              ),
          ],
        ],
      ),
    );
  }
}

class _BucketCard extends StatelessWidget {
  const _BucketCard({required this.bucket});

  final StorageBucketInfo bucket;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.orange.withOpacity(0.2)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.03),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () {
            Clipboard.setData(ClipboardData(text: bucket.name));
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('Bucket "${bucket.name}" copied'),
                duration: const Duration(seconds: 1),
              ),
            );
          },
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.orange.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.folder_open, size: 24, color: Colors.orange),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        bucket.name,
                        style: const TextStyle(
                          fontWeight: FontWeight.w600,
                          fontSize: 14,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        bucket.isPublic ? 'Public Access Enabled' : 'Private',
                        style: TextStyle(
                          fontSize: 12,
                          color: bucket.isPublic ? Colors.red : Colors.green,
                        ),
                      ),
                    ],
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Colors.red.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: const Text(
                    'PUBLIC',
                    style: TextStyle(
                      color: Colors.red,
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _FileCard extends StatelessWidget {
  const _FileCard({required this.path});

  final String path;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Colors.blue.withOpacity(0.05),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.blue.withOpacity(0.2)),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () {
            Clipboard.setData(ClipboardData(text: path));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('File path copied'),
                duration: Duration(seconds: 1),
              ),
            );
          },
          borderRadius: BorderRadius.circular(8),
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                Icon(Icons.insert_drive_file, color: Colors.blue[700]),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    path,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                ),
                Icon(Icons.copy, size: 18, color: Colors.blue[300]),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ============================================
// LIST VIEW - Unified card display
// ============================================

class _ListView extends StatelessWidget {
  const _ListView({required this.findings});

  final List<_FindingItem> findings;

  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
      itemCount: findings.length,
      itemBuilder: (context, index) {
        final finding = findings[index];
        return _FindingCard(finding: finding);
      },
    );
  }
}

class _FindingCard extends StatefulWidget {
  const _FindingCard({required this.finding});

  final _FindingItem finding;

  @override
  State<_FindingCard> createState() => _FindingCardState();
}

class _FindingCardState extends State<_FindingCard> {
  bool _isExpanded = false;

  static const int _maxShortValueLength = 100;
  static const int _maxShortValueLines = 3;

  bool get _isLargeValue {
    final valueStr = widget.finding.value;
    final lineCount = '\n'.allMatches(valueStr).length + 1;
    return valueStr.length > _maxShortValueLength ||
        lineCount > _maxShortValueLines;
  }

  String get _previewValue {
    final valueStr = widget.finding.value;
    final lines = valueStr.split('\n');

    if (lines.length > _maxShortValueLines) {
      return '${lines.take(_maxShortValueLines).join('\n')}...';
    }

    if (valueStr.length > _maxShortValueLength) {
      return '${valueStr.substring(0, _maxShortValueLength)}...';
    }

    return valueStr;
  }

  @override
  Widget build(BuildContext context) {
    final finding = widget.finding;

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.grey.shade200),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.03),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          InkWell(
            onTap: () => _copyValue(context),
            onLongPress: () => _showFullValue(context),
            borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
            child: Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: finding.color.withOpacity(0.05),
                borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                border: Border(
                  bottom: BorderSide(color: finding.color.withOpacity(0.1)),
                ),
              ),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: finding.color.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Icon(finding.icon, size: 14, color: finding.color),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          finding.title,
                          style: TextStyle(
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                            color: Colors.grey.shade800,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          finding.typeLabel,
                          style: TextStyle(
                            fontSize: 11,
                            color: finding.color,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (finding.type != _FindingType.info)
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                      decoration: BoxDecoration(
                        color: Colors.red.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: const Text(
                        'EXPOSED',
                        style: TextStyle(
                          color: Colors.red,
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
          if (_isLargeValue) _buildExpandableValue() else _buildSimpleValue(),
        ],
      ),
    );
  }

  Widget _buildSimpleValue() {
    return InkWell(
      onTap: () => _copyValue(context),
      borderRadius: const BorderRadius.vertical(bottom: Radius.circular(12)),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        child: Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: const Color(0xFFF8F9FA),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.grey.shade200),
          ),
          child: SelectableText(
            widget.finding.value,
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 13,
              color: Colors.grey.shade800,
              height: 1.4,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildExpandableValue() {
    final finding = widget.finding;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(14, 14, 14, 0),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFFF8F9FA),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.grey.shade200),
            ),
            constraints: BoxConstraints(maxHeight: _isExpanded ? 350 : 100),
            child: SingleChildScrollView(
              physics: _isExpanded
                  ? const AlwaysScrollableScrollPhysics()
                  : const NeverScrollableScrollPhysics(),
              child: SelectableText(
                _isExpanded ? finding.value : _previewValue,
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 13,
                  color: Colors.grey.shade800,
                  height: 1.4,
                ),
              ),
            ),
          ),
        ),
        InkWell(
          onTap: () => setState(() => _isExpanded = !_isExpanded),
          borderRadius: const BorderRadius.vertical(bottom: Radius.circular(12)),
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  decoration: BoxDecoration(
                    color: finding.color.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        _isExpanded ? Icons.unfold_less : Icons.unfold_more,
                        size: 16,
                        color: finding.color,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        _isExpanded ? 'Collapse' : 'Expand',
                        style: TextStyle(
                          color: finding.color,
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  void _copyValue(BuildContext context) {
    Clipboard.setData(ClipboardData(text: widget.finding.value));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Copied "${widget.finding.title}" to clipboard'),
        duration: const Duration(seconds: 1),
      ),
    );
  }

  void _showFullValue(BuildContext context) {
    final finding = widget.finding;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.7,
        minChildSize: 0.4,
        maxChildSize: 0.95,
        expand: false,
        builder: (context, scrollController) => Container(
          decoration: const BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: Column(
            children: [
              Center(
                child: Container(
                  margin: const EdgeInsets.only(top: 12),
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: Colors.grey[300],
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),
              Container(
                margin: const EdgeInsets.all(16),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: finding.color.withOpacity(0.05),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: finding.color.withOpacity(0.1)),
                ),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: finding.color.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(finding.icon, size: 20, color: finding.color),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            finding.title,
                            style: TextStyle(
                              fontWeight: FontWeight.w600,
                              fontSize: 16,
                              color: Colors.grey.shade800,
                            ),
                          ),
                          Text(
                            finding.typeLabel,
                            style: TextStyle(fontSize: 12, color: finding.color),
                          ),
                        ],
                      ),
                    ),
                    Material(
                      color: finding.color.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                      child: InkWell(
                        onTap: () {
                          Clipboard.setData(ClipboardData(text: finding.value));
                          Navigator.pop(context);
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Copied to clipboard'),
                              duration: Duration(seconds: 1),
                            ),
                          );
                        },
                        borderRadius: BorderRadius.circular(8),
                        child: Padding(
                          padding: const EdgeInsets.all(8),
                          child: Icon(Icons.copy_rounded, size: 20, color: finding.color),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: SingleChildScrollView(
                  controller: scrollController,
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                  child: Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: const Color(0xFFF8F9FA),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.grey.shade200),
                    ),
                    child: SelectableText(
                      finding.value,
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 13,
                        color: Colors.grey.shade800,
                        height: 1.5,
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ============================================
// TABLE VIEW - Data table display
// ============================================

class _DataTableView extends StatelessWidget {
  const _DataTableView({required this.findings});

  final List<_FindingItem> findings;

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Card(
          elevation: 0,
          clipBehavior: Clip.antiAlias,
          child: Table(
            defaultColumnWidth: const IntrinsicColumnWidth(),
            columnWidths: const {
              0: FixedColumnWidth(80),
              1: FixedColumnWidth(150),
              2: FixedColumnWidth(400),
            },
            border: TableBorder(
              horizontalInside: BorderSide(color: Colors.grey.shade200),
            ),
            children: [
              TableRow(
                decoration: BoxDecoration(color: Colors.grey.shade100),
                children: const [
                  _TableHeader('Type'),
                  _TableHeader('Name'),
                  _TableHeader('Details'),
                ],
              ),
              ...findings.map((finding) => _buildTableRow(context, finding)),
            ],
          ),
        ),
      ),
    );
  }

  TableRow _buildTableRow(BuildContext context, _FindingItem finding) {
    final isLong = finding.value.length > 50 || finding.value.contains('\n');

    return TableRow(
      children: [
        _TableCell(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: finding.color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              finding.typeLabel,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                color: finding.color,
              ),
            ),
          ),
        ),
        _TableCell(
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(finding.icon, size: 16, color: finding.color),
              const SizedBox(width: 8),
              Text(
                finding.title,
                style: TextStyle(
                  fontWeight: FontWeight.w500,
                  fontSize: 13,
                  color: finding.color,
                ),
              ),
            ],
          ),
          onTap: () {
            Clipboard.setData(ClipboardData(text: finding.title));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('Name copied'),
                duration: Duration(seconds: 1),
              ),
            );
          },
        ),
        _TableCell(
          child: Text(
            isLong
                ? '${finding.value.substring(0, 50.clamp(0, finding.value.length))}...'
                : finding.value,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          onTap: () {
            Clipboard.setData(ClipboardData(text: finding.value));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('Value copied'),
                duration: Duration(seconds: 1),
              ),
            );
          },
        ),
      ],
    );
  }
}

class _TableHeader extends StatelessWidget {
  const _TableHeader(this.text);
  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Text(
        text,
        style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
      ),
    );
  }
}

class _TableCell extends StatelessWidget {
  const _TableCell({required this.child, this.onTap});
  final Widget child;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: child,
      ),
    );
  }
}

// ============================================
// JSON VIEW - Raw JSON display
// ============================================

class _JsonView extends StatelessWidget {
  const _JsonView({required this.jsonData});

  final Map<String, dynamic> jsonData;

  String get _jsonString => const JsonEncoder.withIndent('  ').convert(jsonData);

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 80),
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF1E1E1E),
              borderRadius: BorderRadius.circular(12),
            ),
            child: SelectableText(
              _jsonString,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 13,
                color: Color(0xFFD4D4D4),
                height: 1.5,
              ),
            ),
          ),
        ),
        Positioned(
          right: 20,
          bottom: 20,
          child: FloatingActionButton.small(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _jsonString));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('JSON copied to clipboard'),
                  duration: Duration(seconds: 1),
                ),
              );
            },
            child: const Icon(Icons.copy),
          ),
        ),
      ],
    );
  }
}
