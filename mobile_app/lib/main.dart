import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

void main() => runApp(const SocApp());

class SocApp extends StatelessWidget {
  const SocApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Self-Healing SOC',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(useMaterial3: true).copyWith(
        scaffoldBackgroundColor: const Color(0xFF0B1120),
        colorScheme: ColorScheme.dark(primary: const Color(0xFF38BDF8)),
        cardTheme: const CardTheme(color: Color(0xFF111A2E)),
      ),
      home: const LoginPage(),
    );
  }
}

class Api {
  Api(this.baseUrl);
  final String baseUrl;

  Future<String?> login(String username, String password) async {
    final res = await http.post(
      Uri.parse('$baseUrl/api/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'username': username, 'password': password}),
    );
    if (res.statusCode != 200) throw Exception('Login failed (${res.statusCode})');
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('soc_token', body['access_token'] as String);
    await prefs.setString('soc_role', body['role'] as String);
    await prefs.setString('soc_url', baseUrl);
    return body['access_token'] as String;
  }

  Future<Map<String, dynamic>> get(String path, String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl$path'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('$path failed (${res.statusCode})');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<List<dynamic>> getList(String path, String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl$path'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('$path failed (${res.statusCode})');
    return jsonDecode(res.body) as List<dynamic>;
  }

  Future<void> post(String path, String token) async {
    final res = await http.post(
      Uri.parse('$baseUrl$path'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode >= 400) throw Exception('$path failed (${res.statusCode})');
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _username = TextEditingController(text: 'analyst');
  final _password = TextEditingController(text: 'Analyst@12345');
  final _url = TextEditingController(text: 'http://10.0.2.2:8000');
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    SharedPreferences.getInstance().then((p) {
      if (p.getString('soc_url') != null) setState(() => _url.text = p.getString('soc_url')!);
    });
  }

  Future<void> _submit() async {
    setState(() { _busy = true; _error = null; });
    try {
      final token = await Api(_url.text).login(_username.text, _password.text);
      if (!mounted) return;
      Navigator.of(context).pushReplacement(MaterialPageRoute(
        child: DashboardPage(baseUrl: _url.text, token: token!),
      ));
    } catch (e) {
      setState(() { _error = '$e'; _busy = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              const Text('🛡 Self-Healing SOC',
                  style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              Text('AI detection · MITRE ATT&CK · self-healing',
                  style: TextStyle(color: Colors.grey[500])),
              const SizedBox(height: 24),
              TextField(controller: _url,
                  decoration: const InputDecoration(labelText: 'API URL')),
              TextField(controller: _username,
                  decoration: const InputDecoration(labelText: 'Username')),
              TextField(controller: _password, obscureText: true,
                  decoration: const InputDecoration(labelText: 'Password')),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Text(_error!, style: const TextStyle(color: Colors.redAccent)),
                ),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: _busy ? null : _submit,
                child: Text(_busy ? 'Signing in…' : 'Sign in'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class DashboardPage extends StatefulWidget {
  const DashboardPage({super.key, required this.baseUrl, required this.token});
  final String baseUrl;
  final String token;

  @override
  State<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends State<DashboardPage>
    with SingleTickerProviderStateMixin {
  late final Api _api = Api(widget.baseUrl);
  late final TabController _tabs = TabController(length: 3, vsync: this);

  Map<String, dynamic>? _stats;
  List<dynamic> _events = [];
  List<dynamic> _incidents = [];
  String? _error;
  bool get _canAct {
    final role = _stats == null ? '' : '';
    return role != 'viewer';
  }

  Future<void> _refresh() async {
    try {
      final stats = await _api.get('/api/stats', widget.token);
      final events = await _api.getList('/api/events?limit=50', widget.token);
      final incidents = await _api.getList('/api/incidents', widget.token);
      setState(() { _stats = stats; _events = events; _incidents = incidents; _error = null; });
    } catch (e) {
      setState(() => _error = '$e');
    }
  }

  @override
  void initState() { super.initState(); _refresh(); }

  Future<void> _analyze(int id) async {
    try { await _api.post('/api/events/$id/analyze', widget.token); } finally { _refresh(); }
  }

  Future<void> _heal(int id) async {
    try {
      await _api.post('/api/incidents/$id/simulate-response', widget.token);
    } finally { _refresh(); }
  }

  Color _riskColor(num score) =>
      score >= 85 ? Colors.red : score >= 65 ? Colors.orange : Colors.green;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Self-Healing SOC'),
        actions: [
          IconButton(onPressed: _refresh, icon: const Icon(Icons.refresh)),
          IconButton(
            icon: const Icon(Icons.logout),
            onPressed: () async {
              final p = await SharedPreferences.getInstance();
              await p.clear();
              if (!context.mounted) return;
              Navigator.of(context).pushReplacement(
                MaterialPageRoute(child: const LoginPage()),
              );
            },
          ),
        ],
        bottom: TabBar(
          controller: _tabs,
          tabs: const [
            Tab(icon: Icon(Icons.dashboard), text: 'Overview'),
            Tab(icon: Icon(Icons.bolt), text: 'Events'),
            Tab(icon: Icon(Icons.local_hospital), text: 'Incidents'),
          ],
        ),
      ),
      body: _error != null && _stats == null
          ? Center(child: Text(_error!, style: const TextStyle(color: Colors.redAccent)))
          : RefreshIndicator(
              onRefresh: _refresh,
              child: TabBarView(
                controller: _tabs,
                children: [_overview(), _eventsTab(), _incidentsTab()],
              ),
            ),
    );
  }

  Widget _statCard(String label, dynamic value, Color color) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('$value', style: TextStyle(fontSize: 26, fontWeight: FontWeight.bold, color: color)),
            const SizedBox(height: 2),
            Text(label.toUpperCase(),
                style: const TextStyle(fontSize: 11, letterSpacing: 1)),
          ],
        ),
      ),
    );
  }

  Widget _overview() {
    final s = _stats ?? {};
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        GridView.count(
          crossAxisCount: 2,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          childAspectRatio: 1.9,
          mainAxisSpacing: 8,
          crossAxisSpacing: 8,
          children: [
            _statCard('Events', s['total_events'] ?? '-', Colors.white),
            _statCard('Incidents', s['total_incidents'] ?? '-', const Color(0xFF38BDF8)),
            _statCard('Critical', s['critical_incidents'] ?? '-', Colors.redAccent),
            _statCard('Healed', s['healed_incidents'] ?? '-', Colors.greenAccent),
          ],
        ),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Text('Average risk score',
                  style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              Text('${s['avg_risk'] ?? '-'} / 100',
                  style: TextStyle(
                    fontSize: 22,
                    color: _riskColor((s['avg_risk'] as num?) ?? 0),
                  )),
            ]),
          ),
        ),
        const ListTile(
          leading: Text('🤖'),
          title: Text('ML anomaly detection active'),
          subtitle: Text('Isolation Forest + explainable risk scoring'),
        ),
      ],
    );
  }

  Widget _eventsTab() {
    return ListView.builder(
      itemCount: _events.length,
      itemBuilder: (context, i) {
        final e = _events[i] as Map<String, dynamic>;
        final analyzed = e['analyzed'] == true;
        return Card(
          margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: ListTile(
            title: Text('${e['event_type']} · ${e['endpoint']}'),
            subtitle: Text(analyzed
                ? 'risk ${e['risk_score']} ${e['mitre_technique'] ?? ''}'
                : 'not analyzed yet'),
            trailing: analyzed
                ? Chip(
                    label: Text('${e['severity']}',
                        style: TextStyle(color: _riskColor((e['risk_score'] as num?) ?? 0))),
                  )
                : FilledButton.tonal(
                    onPressed: () => _analyze(e['id'] as int),
                    child: const Text('Analyze'),
                  ),
          ),
        );
      },
    );
  }

  Widget _incidentsTab() {
    return ListView.builder(
      itemCount: _incidents.length,
      itemBuilder: (context, i) {
        final inc = _incidents[i] as Map<String, dynamic>;
        final resolved = inc['status'] == 'resolved';
        return Card(
          margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: ListTile(
            title: Text('#${inc['id']} ${inc['title']}'),
            subtitle: Text(
                '${inc['priority'].toString().toUpperCase()} · risk ${inc['risk_score']}'
                '\nresponse: ${inc['response_status']} · healing: ${inc['healing_status']}'),
            isThreeLine: true,
            trailing: resolved
                ? const Icon(Icons.check_circle, color: Colors.greenAccent)
                : FilledButton.tonal(
                    onPressed: () => _heal(inc['id'] as int),
                    child: const Text('Heal'),
                  ),
          ),
        );
      },
    );
  }
}
