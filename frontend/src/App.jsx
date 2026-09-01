import { useCallback, useEffect, useState } from 'react'
import {
  Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'

const API = ''

async function api(path, { method = 'GET', token, body } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw new Error(detail.detail || `${res.status} ${res.statusText}`)
  }
  return res.json()
}

function Login({ onLogin }) {
  const [username, setUsername] = useState('analyst')
  const [password, setPassword] = useState('Analyst@12345')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const data = await api('/api/auth/login', { method: 'POST', body: { username, password } })
      localStorage.setItem('soc_token', data.access_token)
      localStorage.setItem('soc_role', data.role)
      onLogin(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <h1>🛡 Self-Healing SOC</h1>
      <p className="muted">AI-powered detection · MITRE ATT&CK mapping · simulated self-healing</p>
      <form className="card login-card" onSubmit={submit}>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" />
        {error && <div className="error">{error}</div>}
        <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <span className="muted">Demo: analyst / Analyst@12345 · admin / Admin@12345 · viewer / Viewer@12345</span>
      </form>
    </div>
  )
}

function StatCard({ title, value, tone }) {
  return (
    <div className={`card stat ${tone || ''}`}>
      <h3>{title}</h3>
      <div className="value">{value}</div>
    </div>
  )
}

function Dashboard({ token, role, onLogout }) {
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [incidents, setIncidents] = useState([])
  const [error, setError] = useState('')
  const canAct = role === 'analyst' || role === 'admin'

  const refresh = useCallback(async () => {
    try {
      const [s, e, i] = await Promise.all([
        api('/api/stats', { token }),
        api('/api/events?limit=50', { token }),
        api('/api/incidents', { token }),
      ])
      setStats(s)
      setEvents(e)
      setIncidents(i)
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [token])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  }, [refresh])

  async function analyze(id) {
    try {
      await api(`/api/events/${id}/analyze`, { method: 'POST', token })
      refresh()
    } catch (err) {
      setError(err.message)
    }
  }

  async function simulateResponse(id) {
    try {
      await api(`/api/incidents/${id}/simulate-response`, { method: 'POST', token })
      refresh()
    } catch (err) {
      setError(err.message)
    }
  }

  const chartData = Object.entries(
    events.reduce((acc, ev) => {
      acc[ev.event_type] = (acc[ev.event_type] || 0) + 1
      return acc
    }, {}),
  ).map(([type, count]) => ({ type, count }))

  return (
    <>
      <header className="topbar">
        <h1>🛡 Self-Healing SOC Dashboard</h1>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <span className="user">role: {role} · auto-refresh 3s</span>
          <button className="ghost" onClick={onLogout}>Logout</button>
        </div>
      </header>

      <main className="layout">
        {error && <div className="error">⚠ {error}</div>}

        <section className="stats-grid">
          <StatCard title="Events" value={stats?.total_events ?? '–'} />
          <StatCard title="Incidents" value={stats?.total_incidents ?? '–'} accent />
          <StatCard title="Critical" value={stats?.critical_incidents ?? '–'} danger />
          <StatCard title="Healed" value={stats?.healed_incidents ?? '–'} ok />
          <StatCard title="Avg risk" value={stats?.avg_risk ?? '–'} accent />
        </section>

        <section className="card chart-card">
          <h2 className="section-title">SOC overview — events by type</h2>
          <ResponsiveContainer width="100%" height="85%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="type" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#111a2e', border: '1px solid #1e293b' }} />
              <Bar dataKey="count" fill="#38bdf8" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section className="card">
          <h2 className="section-title">Security events</h2>
          <table>
            <thead>
              <tr>
                <th>#</th><th>Endpoint</th><th>Type</th><th>Severity</th>
                <th>Risk</th><th>MITRE ATT&CK</th><th>Status</th>{canAct && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr key={ev.id}>
                  <td>{ev.id}</td>
                  <td>{ev.endpoint}</td>
                  <td>{ev.event_type}</td>
                  <td><span className={`badge ${ev.severity}`}>{ev.severity}</span></td>
                  <td>{ev.analyzed ? ev.risk_score : '–'}</td>
                  <td>{ev.mitre_technique
                    ? <span className="badge mitre">{ev.mitre_technique.split(' ').slice(0, 2).join(' ')}</span>
                    : '–'}</td>
                  <td>{ev.analyzed ? 'analyzed' : 'pending'}</td>
                  {canAct && (
                    <td>
                      {!ev.analyzed && (
                        <button onClick={() => analyze(ev.id)}>Analyze</button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section className="card">
          <h2 className="section-title">Incidents &amp; self-healing</h2>
          <table>
            <thead>
              <tr>
                <th>#</th><th>Title</th><th>Priority</th><th>Risk</th>
                <th>Response</th><th>Healing</th><th>Status</th>{canAct && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => (
                <tr key={inc.id}>
                  <td>{inc.id}</td>
                  <td>{inc.title}</td>
                  <td><span className={`badge ${inc.priority}`}>{inc.priority}</span></td>
                  <td>{inc.risk_score}</td>
                  <td>{inc.response_status}</td>
                  <td><span className={`badge ${inc.healing_status}`}>{inc.healing_status}</span></td>
                  <td>{inc.status}</td>
                  {canAct && (
                    <td className="row-actions">
                      {inc.status !== 'resolved'
                        ? <button onClick={() => simulateResponse(inc.id)}>Simulate response</button>
                        : <span className="badge validated">healed</span>}
                      <a className="pdf" href={`${API}/api/reports/incident/${inc.id}.pdf`}
                         target="_blank" rel="noreferrer">PDF</a>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <p className="muted">
          All automated responses are recorded simulations only — no live firewalls, hosts or
          accounts are modified. Educational final-year project.
        </p>
      </main>
    </>
  )
}

export default function App() {
  const [auth, setAuth] = useState(() => {
    const token = localStorage.getItem('soc_token')
    return token ? { access_token: token, role: localStorage.getItem('soc_role') || 'viewer' } : null
  })

  if (!auth) {
    return <Login onLogin={(data) => {
      localStorage.setItem('soc_role', data.role)
      setAuth(data)
    }} />
  }

  return (
    <Dashboard
      token={auth.access_token}
      role={auth.role}
      onLogout={() => {
        localStorage.clear()
        setAuth(null)
      }}
    />
  )
}
