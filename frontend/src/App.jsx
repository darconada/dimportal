import React, { useEffect, useMemo, useRef, useState } from 'react'
import ResultsTable from './components/ResultsTable.jsx'
import {
  doSearch,
  getLayer3domains,
  loginRequest,
  logoutRequest,
  fetchSession,
  listSubnetIps,
  reserveIp as reserveIpRequest,
  releaseIp as releaseIpRequest,
  editIp as editIpRequest,
  createDnsRecord,
  detectLayer3domain,
  fetchDnsView,
  importIpInfo,
  importDryrun,
  importExecute
} from './api.js'

const TABS = [
  { key: 'consultas-acs', label: 'Consultas ACS' },
  { key: 'consultas-ionos', label: 'Consultas IONOS' },
  { key: 'gestion-dns', label: 'Gestión DNS' },
  { key: 'importacion-ips', label: 'Importación IPs' }
]

const SEARCH_TYPES_ACS = [
  { value: 'pool', label: 'Pool' },
  { value: 'subnet', label: 'Subred (CIDR o parcial)' },
  { value: 'vlan', label: 'VLAN' },
  { value: 'dns', label: 'DNS (FQDN)' },
  { value: 'ip', label: 'IP' },
  { value: 'device', label: 'Device' }
]

const SEARCH_TYPES_IONOS = [
  { value: 'subnet', label: 'Subred (CIDR o parcial)' },
  { value: 'ip', label: 'IP' }
]

const PLACEHOLDERS = {
  pool: 'es-lgr-pl-...-v4',
  subnet: '192.168.1.0/24 o 192.168.1',
  vlan: '623',
  dns: 'host.arsysnet.lan.',
  ip: '10.140.16.10',
  device: 'es-glb-ins-ifw01-01'
}

const paletteDark = {
  bg: '#0f1724',
  card: '#172337',
  tableHeader: '#21314c',
  tableRow: '#172337',
  text: '#f1f5ff',
  muted: '#a3b3d1',
  border: '#253553',
  primary: '#6f9dff',
  sigma: '#21314c',
  chipBg: '#21314c',
  chipText: '#e8edff',
  danger: '#d75f5f',
  success: '#2aa35c',
  menuBg: '#172337'
}

const paletteLight = {
  bg: '#f5f6f9',
  card: '#ffffff',
  tableHeader: '#e7ecf6',
  tableRow: '#ffffff',
  text: '#1d2733',
  muted: '#4a5461',
  border: '#d5d9e2',
  primary: '#005ac1',
  sigma: '#e7ecf6',
  chipBg: '#e7ecf6',
  chipText: '#1d2733',
  danger: '#c44444',
  success: '#1e874a',
  menuBg: '#ffffff'
}

const containerStyle = { maxWidth: 1200, margin: '0 auto', padding: '0 1rem' }
const FQDN_REGEX = /^([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+\.$/
const IPV4_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const SUBNET_PARTIAL_REGEX = /^(\d{1,3})(\.\d{1,3}){0,2}\.?$/

function LoginScreen({ onSubmit, error, loggingIn, palette }) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: palette.bg }}>
      <div
        style={{
          background: palette.card,
          color: palette.text,
          border: `1px solid ${palette.border}`,
          borderRadius: 14,
          boxShadow: '0 12px 30px rgba(7,12,26,0.45)',
          width: 'min(420px, 100%)',
          padding: '2rem'
        }}
      >
        <h1 style={{ marginTop: 0, marginBottom: 4 }}>Portal DIM</h1>
        <p style={{ color: palette.muted, marginTop: 0, marginBottom: 16 }}>Accede con tus credenciales corporativas</p>
        {error ? <div style={{ color: palette.danger, marginBottom: 12 }}>{error}</div> : null}
        <form
          onSubmit={(e) => {
            e.preventDefault()
            const data = new FormData(e.currentTarget)
            onSubmit({
              username: data.get('username')?.toString() || '',
              password: data.get('password')?.toString() || ''
            })
          }}
        >
          <div style={{ marginBottom: 12 }}>
            <label style={{ display: 'block', color: palette.muted, marginBottom: 6 }}>Usuario</label>
            <input
              name="username"
              required
              autoComplete="username"
              style={{
                width: '100%',
                padding: '0.65rem 0.75rem',
                borderRadius: 10,
                border: `1px solid ${palette.border}`,
                background: palette.tableRow,
                color: palette.text
              }}
            />
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', color: palette.muted, marginBottom: 6 }}>Contraseña</label>
            <input
              name="password"
              type="password"
              required
              autoComplete="current-password"
              style={{
                width: '100%',
                padding: '0.65rem 0.75rem',
                borderRadius: 10,
                border: `1px solid ${palette.border}`,
                background: palette.tableRow,
                color: palette.text
              }}
            />
          </div>
          <button
            type="submit"
            disabled={loggingIn}
            style={{
              width: '100%',
              padding: '0.75rem',
              background: palette.primary,
              color: '#fff',
              border: 'none',
              borderRadius: 10,
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            {loggingIn ? 'Accediendo…' : 'Iniciar sesión'}
          </button>
        </form>
      </div>
    </div>
  )
}

export default function App() {
  const [theme, setTheme] = useState(() => {
    if (typeof window === 'undefined') return 'dark'
    try {
      const stored = localStorage.getItem('dim-theme')
      if (stored === 'light' || stored === 'dark') return stored
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
      return prefersDark ? 'dark' : 'light'
    } catch {
      return 'dark'
    }
  })
  const [activeTab, setActiveTab] = useState('consultas-acs')
  const [type, setType] = useState('pool')
  const [q, setQ] = useState('')
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [pageSize, setPageSize] = useState(10)
  const [l3ds, setL3ds] = useState([])
  const [l3d, setL3d] = useState('')
  const [auth, setAuth] = useState(false)
  const [loginError, setLoginError] = useState('')
  const [loggingIn, setLoggingIn] = useState(false)
  const [userName, setUserName] = useState('')
  const [sessionExpired, setSessionExpired] = useState(false)

  // Importación (UI aproximada)
  const [importFile, setImportFile] = useState(null)
  const [importRows, setImportRows] = useState([])
  const [importResolving, setImportResolving] = useState(false)
  const [importSearch, setImportSearch] = useState('')
  const [importPageSize, setImportPageSize] = useState('10')
  const fileInputRef = useRef(null)
  const [dnsView, setDnsView] = useState('Interna')
  const [subnetModalOpen, setSubnetModalOpen] = useState(false)
  const [subnetModalTitle, setSubnetModalTitle] = useState('')
  const [subnetModalLayer3, setSubnetModalLayer3] = useState('')
  const [subnetModalPool, setSubnetModalPool] = useState('')
  const [subnetModalRows, setSubnetModalRows] = useState([])
  const [subnetModalStatus, setSubnetModalStatus] = useState('all')
  const [subnetModalLoading, setSubnetModalLoading] = useState(false)
  const [subnetModalError, setSubnetModalError] = useState('')
  const [subnetSearch, setSubnetSearch] = useState('')
  const [subnetPageSize, setSubnetPageSize] = useState('10')
  const [reserveModalOpen, setReserveModalOpen] = useState(false)
  const [reserveIp, setReserveIp] = useState('')
  const [reserveLayer3, setReserveLayer3] = useState('')
  const [reservePool, setReservePool] = useState('')
  const [reserveCreateDns, setReserveCreateDns] = useState(true)
  const [reserveFqdn, setReserveFqdn] = useState('')
  const [reserveView, setReserveView] = useState('default')
  const [reserveComment, setReserveComment] = useState('')
  const [reserveSaving, setReserveSaving] = useState(false)
  const [reserveError, setReserveError] = useState('')
  const [reserveSuccess, setReserveSuccess] = useState('')
  const [releaseModalOpen, setReleaseModalOpen] = useState(false)
  const [releaseIp, setReleaseIp] = useState('')
  const [releasePool, setReleasePool] = useState('')
  const [releaseSaving, setReleaseSaving] = useState(false)
  const [releaseError, setReleaseError] = useState('')
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [editIpValue, setEditIpValue] = useState('')
  const [editPool, setEditPool] = useState('')
  const [editLayer3, setEditLayer3] = useState('')
  const [editDns, setEditDns] = useState('')
  const [editInitialDns, setEditInitialDns] = useState('')
  const [editComment, setEditComment] = useState('')
  const [editInitialComment, setEditInitialComment] = useState('')
  const [editView, setEditView] = useState('default')
  const [editViewInitial, setEditViewInitial] = useState('default')
  const [editDetectedViews, setEditDetectedViews] = useState([])
  const [editError, setEditError] = useState('')
  const [editSaving, setEditSaving] = useState(false)
  const [ipActionResult, setIpActionResult] = useState(null)
  const [pendingSubnetRefresh, setPendingSubnetRefresh] = useState(false)
  const [actionResetNonce, setActionResetNonce] = useState(0)
  const [commandMessage, setCommandMessage] = useState('')
  const manualReviewLabel = 'Error: Revisar manualmente'
  const [importConfirmOpen, setImportConfirmOpen] = useState(false)
  const [importDryrunOpen, setImportDryrunOpen] = useState(false)
  const [importDryrunResults, setImportDryrunResults] = useState([])
  const [importDryrunLoading, setImportDryrunLoading] = useState(false)
  const [importDryrunError, setImportDryrunError] = useState('')
  const [importExecuteOpen, setImportExecuteOpen] = useState(false)
  const [importExecuteResults, setImportExecuteResults] = useState([])
  const [importExecuteLoading, setImportExecuteLoading] = useState(false)
  const [importExecuteError, setImportExecuteError] = useState('')
  const importButtonsDisabled =
    importResolving || importDryrunLoading || importExecuteLoading || !importRows.length
  // Gestión DNS (aislado)
  const [dnsSectionAction, setDnsSectionAction] = useState('create-single')
  const [dnsCreateFqdn, setDnsCreateFqdn] = useState('')
  const [dnsCreateIp, setDnsCreateIp] = useState('')
  const [dnsCreateView, setDnsCreateView] = useState('Interna')
  const [dnsCreateError, setDnsCreateError] = useState('')
  const [dnsCreateMessage, setDnsCreateMessage] = useState('')
  const [dnsCreateLoading, setDnsCreateLoading] = useState(false)
  const [dnsCreateLayer3, setDnsCreateLayer3] = useState('')
  const [dnsCreateConfirmOpen, setDnsCreateConfirmOpen] = useState(false)
  const [dnsCreateResult, setDnsCreateResult] = useState(null)
  const [dnsCreateDryrunOpen, setDnsCreateDryrunOpen] = useState(false)
  const [dnsCreateDryrunLoading, setDnsCreateDryrunLoading] = useState(false)
  const [dnsCreateDryrunResults, setDnsCreateDryrunResults] = useState([])

  const palette = theme === 'dark' ? paletteDark : paletteLight

  const resetUiState = () => {
    setActiveTab('consultas-acs')
    setType('pool')
    setQ('')
    setRows([])
    setError('')
    setPageSize(10)
    setL3d('')
    setSubnetModalOpen(false)
    setSubnetModalRows([])
    setSubnetModalError('')
    setSubnetModalLoading(false)
    setSubnetSearch('')
    setSubnetPageSize('10')
    setReserveModalOpen(false)
    setReserveIp('')
    setReserveLayer3('')
    setReservePool('')
    setReserveCreateDns(true)
    setReserveFqdn('')
    setReserveView('default')
    setReserveComment('')
    setSessionExpired(false)
    setIpActionResult(null)
    setPendingSubnetRefresh(false)
    setReleaseModalOpen(false)
    setReleaseIp('')
    setReleasePool('')
    setReleaseSaving(false)
    setReleaseError('')
    setActionResetNonce(0)
    setEditModalOpen(false)
    setEditIpValue('')
    setEditPool('')
    setEditLayer3('')
    setEditDns('')
    setEditInitialDns('')
    setEditComment('')
    setEditInitialComment('')
    setEditView('default')
    setEditViewInitial('default')
    setEditError('')
    setEditSaving(false)
  }

  useEffect(() => {
    try {
      localStorage.setItem('dim-theme', theme)
    } catch (err) {
      // si el almacenamiento no está disponible, ignoramos el error
    }
  }, [theme])

  useEffect(() => {
    getLayer3domains().then(setL3ds).catch(() => {})
  }, [])

  useEffect(() => {
    fetchSession()
      .then((data) => {
        setAuth(true)
        setUserName(data.display_name || data.username || '')
      })
      .catch(() => {
        setAuth(false)
      })
  }, [])

  useEffect(() => {
    const allowed = activeTab === 'consultas-acs' ? SEARCH_TYPES_ACS : SEARCH_TYPES_IONOS
    if (activeTab === 'consultas-ionos' && !['subnet', 'ip'].includes(type)) {
      setType(allowed[0].value)
      setQ('')
      setRows([])
      setPageSize(10)
      setError('')
    }
    if (activeTab === 'consultas-acs' && !SEARCH_TYPES_ACS.find((t) => t.value === type)) {
      setType(SEARCH_TYPES_ACS[0].value)
      setQ('')
      setRows([])
      setPageSize(10)
      setError('')
    }
    // Al cambiar de pestaña, limpiamos consulta y resultados
    setQ('')
    setRows([])
    setPageSize(10)
    setError('')
  }, [activeTab])

  useEffect(() => {
    // Al cambiar tipo de búsqueda dentro de la pestaña, vaciamos consulta y resultados
    setQ('')
    setRows([])
    setPageSize(10)
    setDnsView('Interna')
    setError('')
  }, [type])

  const dnsInlineError = useMemo(() => {
    if (!(activeTab === 'consultas-acs' && type === 'dns')) return ''
    const normalized = q.trim()
    if (!normalized) return ''
    if (!normalized.endsWith('.')) return 'El FQDN debe finalizar en punto.'
    if (!FQDN_REGEX.test(normalized)) return 'FQDN inválido'
    return ''
  }, [activeTab, type, q])

  const isDnsInputInvalid = Boolean(dnsInlineError)
  const subnetInlineError = useMemo(() => {
    if (type !== 'subnet') return ''
    const value = q.trim()
    if (!value) return ''

    const invalidMsg = 'Debe introducir una subred (CIDR o parcial) válida.'

    // CIDR completo
    if (value.includes('/')) {
      const [ipPart, prefixPart] = value.split('/')
      if (!ipPart || prefixPart === undefined) return invalidMsg
      const prefix = Number(prefixPart)
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return invalidMsg
      const octets = ipPart.split('.')
      if (octets.length !== 4) return invalidMsg
      const validOctets = octets.every((o) => {
        if (!/^\d+$/.test(o)) return false
        const n = Number(o)
        return n >= 0 && n <= 255
      })
      return validOctets ? '' : invalidMsg
    }

    // Subred parcial: 1 a 3 octetos
    if (!SUBNET_PARTIAL_REGEX.test(value)) return invalidMsg
    const cleaned = value.replace(/\.$/, '')
    const octets = cleaned.split('.').filter(Boolean)
    if (octets.length < 1 || octets.length > 3) return invalidMsg
    const validOctets = octets.every((o) => {
      if (!/^\d+$/.test(o)) return false
      const n = Number(o)
      return n >= 0 && n <= 255
    })
    return validOctets ? '' : invalidMsg
  }, [type, q])

  const isSubnetInputInvalid = Boolean(subnetInlineError)
  const isDeviceSearch = activeTab === 'consultas-acs' && type === 'device'
  const isSearchDisabled =
    isDnsInputInvalid ||
    isSubnetInputInvalid ||
    (isDeviceSearch && !q.trim())

  const handleSessionExpired = () => {
    setAuth(false)
    resetUiState()
    setSessionExpired(true)
  }

  const onSearch = async (e) => {
    e.preventDefault()
    setError('')
    setPageSize(10)
    const normalized = q.trim()
    if (type === 'dns') {
      if (!normalized) {
        setError('Introduce un FQDN')
        setRows([])
        return
      }
      if (dnsInlineError) {
        setError(dnsInlineError)
        setRows([])
        return
      }
    }
    if (type === 'subnet') {
      if (!normalized) {
        setError('Introduce una subred')
        setRows([])
        return
      }
      if (subnetInlineError) {
        setError(subnetInlineError)
        setRows([])
        return
      }
    }
    if (type === 'device') {
      if (!normalized) {
        setError('Introduce un device')
        setRows([])
        return
      }
    }
    setLoading(true)
    setRows([])
    try {
      const params = { type, q: normalized || q }
      if (activeTab === 'consultas-ionos') params.scope = 'ionos'
      if (type === 'dns' && isDnsArsyscloud) {
        if (dnsView === 'Interna') params.view = 'internal'
        else if (dnsView === 'Pública') params.view = 'public'
        else if (dnsView === 'Interna/Pública') params.view = 'both'
      }
      if (l3d) params.layer3domain = l3d
      const data = await doSearch(params)
      setRows(data)
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      const msg = err?.message || ''
      const lower = msg.toLowerCase()
      if (lower.includes('sin resultados') || lower.includes('no records found')) {
        setError('')
        setRows([])
      } else {
        setError(msg)
      }
    } finally {
      setLoading(false)
    }
  }

  const handleSubnetAction = async ({ subnet, action, layer3domain, pool }) => {
    const statusMap = { all: 'all', free: 'free', used: 'used' }
    const targetStatus = statusMap[action] || 'all'
    const targetSubnet = (subnet || '').trim()
    const targetLayer3 = (layer3domain || '').trim()
    const targetPool = (pool || '').trim()
    if (!targetSubnet || !targetLayer3) return

    setSubnetModalTitle(targetSubnet)
    setSubnetModalLayer3(targetLayer3)
    setSubnetModalPool(targetPool)
    setSubnetModalStatus(targetStatus)
    setSubnetModalOpen(true)
    setSubnetModalLoading(true)
    setSubnetModalError('')
    setSubnetModalRows([])
    setSubnetPageSize('10')
    setSubnetSearch('')
    setReserveModalOpen(false)

    try {
      const data = await listSubnetIps({
        subnet: targetSubnet,
        layer3domain: targetLayer3 || undefined,
        status: targetStatus,
        limit: 256
      })
      setSubnetModalRows(Array.isArray(data) ? data : [])
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      setSubnetModalError(err.message || 'No se pudieron obtener las IPs de la subred')
    } finally {
      setSubnetModalLoading(false)
    }
  }

  const visibleRows = useMemo(() => rows.slice(0, pageSize || rows.length), [rows, pageSize])
  const subnetDisplayedRows = useMemo(() => {
    if (!subnetModalRows.length) return []
    if (subnetPageSize === 'all') return subnetModalRows
    const size = Number(subnetPageSize)
    if (Number.isNaN(size) || size <= 0) return subnetModalRows
    return subnetModalRows.slice(0, size)
  }, [subnetModalRows, subnetPageSize])
  const importFilteredRows = useMemo(() => {
    if (!importRows.length) return []
    const term = importSearch.trim().toLowerCase()
    if (!term) return importRows
    return importRows.filter((row) => {
      const values = [
        row.ip || '',
        row.hostname || '',
        row.pool || '',
        row.layer3domain || '',
        row.detail || ''
      ]
      return values.some((val) => val.toLowerCase().includes(term))
    })
  }, [importRows, importSearch])
  const importDisplayedRows = useMemo(() => {
    if (!importFilteredRows.length) return []
    if (importPageSize === 'all') return importFilteredRows
    const size = Number(importPageSize)
    if (Number.isNaN(size) || size <= 0) return importFilteredRows
    return importFilteredRows.slice(0, size)
  }, [importFilteredRows, importPageSize])

  const isReserveFqdnInvalid = useMemo(() => {
    if (!reserveCreateDns) return ''
    const value = reserveFqdn.trim()
    if (!value) return ''
    if (!value.endsWith('.')) return 'El FQDN debe finalizar en punto.'
    if (!FQDN_REGEX.test(value)) return 'FQDN inválido'
    return ''
  }, [reserveCreateDns, reserveFqdn])
  const dnsCreateFqdnInvalid = useMemo(() => {
    const value = dnsCreateFqdn.trim()
    if (!value) return ''
    if (!value.endsWith('.')) return 'El FQDN debe finalizar en punto.'
    if (!FQDN_REGEX.test(value)) return 'FQDN inválido'
    return ''
  }, [dnsCreateFqdn])
  const dnsCreateIpInvalid = useMemo(() => {
    const value = dnsCreateIp.trim()
    if (!value) return ''
    if (!IPV4_REGEX.test(value)) return 'IP inválida'
    return ''
  }, [dnsCreateIp])

  const editDnsInvalid = useMemo(() => {
    if (!editDns.trim()) return ''
    if (!editDns.trim().endsWith('.')) return 'El FQDN debe finalizar en punto.'
    if (!FQDN_REGEX.test(editDns.trim())) return 'FQDN inválido'
    return ''
  }, [editDns])
  const editRequiresView = useMemo(() => {
    const val = editDns.trim().toLowerCase()
    return val.includes('.arsyscloud.tools')
  }, [editDns])
  const currentEditViewNormalized = useMemo(() => {
    const map = { Interna: 'internal', 'Pública': 'public', 'Interna/Pública': 'both' }
    return map[editViewInitial] || editViewInitial || 'default'
  }, [editViewInitial])
  const editViewOptions = useMemo(() => {
    if (!editRequiresView) return [{ value: 'default', label: 'default', disabled: true }]
    const labelMap = { internal: 'Interna', public: 'Pública', both: 'Interna/Pública' }
    const opts = []
    // Mostramos la vista actual detectada como referencia (deshabilitada)
    if (currentEditViewNormalized !== 'default') {
      const currLabel = labelMap[currentEditViewNormalized] || currentEditViewNormalized
      opts.push({
        value: labelMap[currentEditViewNormalized] || currentEditViewNormalized,
        label: `Actual: ${currLabel}`,
        disabled: true
      })
    }
    ;['Interna', 'Pública', 'Interna/Pública'].forEach((opt) => {
      const normalized = { Interna: 'internal', 'Pública': 'public', 'Interna/Pública': 'both' }[opt]
      opts.push({ value: opt, label: opt, disabled: false, detected: editDetectedViews.includes(normalized) })
    })
    return opts
  }, [editRequiresView, currentEditViewNormalized, editDetectedViews])
  useEffect(() => {
    if (!editRequiresView) {
      setEditView('default')
      setEditDetectedViews([])
    } else if (!['Interna', 'Pública', 'Interna/Pública'].includes(editView)) {
      setEditView('Interna')
    }
  }, [editRequiresView, editView])

  const reserveRequiresView = reserveCreateDns && reserveFqdn.trim().toLowerCase().includes('.arsyscloud.tools.')
  const reserveViews = reserveRequiresView ? ['Interna', 'Pública', 'Interna/Pública'] : ['default']
  useEffect(() => {
    if (!reserveRequiresView) {
      setReserveView('default')
    } else if (!reserveViews.includes(reserveView)) {
      setReserveView('Interna')
    }
  }, [reserveRequiresView, reserveView, reserveViews])
  const dnsCreateRequiresView = useMemo(
    () => dnsCreateFqdn.trim().toLowerCase().includes('.arsyscloud.tools'),
    [dnsCreateFqdn]
  )
  const dnsCreateViewOptions = ['Interna', 'Pública', 'Interna/Pública']
  const dnsCreateSubmitDisabled = useMemo(
    () => !!dnsCreateFqdnInvalid || !!dnsCreateIpInvalid || !dnsCreateFqdn.trim() || !dnsCreateIp.trim(),
    [dnsCreateFqdnInvalid, dnsCreateIpInvalid, dnsCreateFqdn, dnsCreateIp]
  )

  // Al volver a la pestaña de Importación, reseteamos estado de CSV/tabla
  useEffect(() => {
    if (activeTab === 'importacion-ips') {
      setImportFile(null)
      setImportRows([])
      setImportResolving(false)
      setImportSearch('')
      setImportPageSize('10')
    }
  }, [activeTab])
  useEffect(() => {
    if (activeTab !== 'gestion-dns') return
    setDnsSectionAction('create-single')
    setDnsCreateFqdn('')
    setDnsCreateIp('')
    setDnsCreateView('Interna')
    setDnsCreateError('')
    setDnsCreateMessage('')
    setDnsCreateLoading(false)
    setDnsCreateLayer3('')
    setDnsCreateConfirmOpen(false)
    setDnsCreateResult(null)
    setDnsCreateDryrunOpen(false)
    setDnsCreateDryrunLoading(false)
    setDnsCreateDryrunResults([])
  }, [activeTab])
  useEffect(() => {
    setDnsCreateError('')
    setDnsCreateMessage('')
    setDnsCreateLoading(false)
    setDnsCreateConfirmOpen(false)
    setDnsCreateDryrunOpen(false)
    setDnsCreateDryrunResults([])
  }, [dnsSectionAction])

  const subnetFilteredRows = useMemo(() => {
    if (!subnetSearch.trim()) return subnetDisplayedRows
    const term = subnetSearch.trim().toLowerCase()
    return subnetDisplayedRows.filter((row) => {
      const candidates = [row.ip || '', row.status || '', row.ptr_target || '', row.comment || '']
      return candidates.some((val) => val.toLowerCase().includes(term))
    })
  }, [subnetDisplayedRows, subnetSearch])
  const resetDnsCreateForm = () => {
    setDnsCreateFqdn('')
    setDnsCreateIp('')
    setDnsCreateView('Interna')
    setDnsCreateError('')
    setDnsCreateMessage('')
    setDnsCreateLoading(false)
    setDnsCreateLayer3('')
    setDnsCreateConfirmOpen(false)
    setDnsCreateDryrunOpen(false)
    setDnsCreateDryrunLoading(false)
    setDnsCreateDryrunResults([])
  }

  const buildDnsCreatePayload = () => {
    const viewMapping = {
      Interna: 'internal',
      'Pública': 'public',
      'Interna/Pública': 'both',
      default: 'default',
      internal: 'internal',
      public: 'public',
      both: 'both'
    }
    return {
      name: dnsCreateFqdn.trim(),
      record_type: 'A',
      value: dnsCreateIp.trim(),
      view: dnsCreateRequiresView ? viewMapping[dnsCreateView] || 'internal' : 'default',
      layer3domain: (dnsCreateLayer3 || l3d || '').trim() || undefined
    }
  }

  const handleDnsCreateSubmit = async (e) => {
    e.preventDefault()
    setDnsCreateError('')
    setDnsCreateMessage('')
    if (!dnsCreateFqdn.trim()) {
      setDnsCreateError('Debes indicar un FQDN.')
      return
    }
    if (dnsCreateFqdnInvalid) {
      setDnsCreateError(dnsCreateFqdnInvalid)
      return
    }
    if (!dnsCreateIp.trim()) {
      setDnsCreateError('Debes indicar una IP.')
      return
    }
    if (dnsCreateIpInvalid) {
      setDnsCreateError(dnsCreateIpInvalid)
      return
    }
    setDnsCreateLoading(true)
    try {
      const resp = await detectLayer3domain({ ip: dnsCreateIp.trim() })
      const layer = resp?.layer3domain || ''
      setDnsCreateLayer3(layer)
      setDnsCreateConfirmOpen(true)
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      setDnsCreateError(err.message || 'No se pudo determinar el layer3domain de la IP')
    } finally {
      setDnsCreateLoading(false)
    }
  }

  const handleDnsCreateDryrun = () => {
    const payload = { ...buildDnsCreatePayload(), dry_run: true }
    setDnsCreateDryrunLoading(true)
    createDnsRecord(payload)
      .then((resp) => {
        const entries = []
        if (resp?.command) {
          entries.push({
            command: resp.command,
            output: (resp.output || '').toString().trim() || 'OK'
          })
        }
        setDnsCreateDryrunResults(entries)
        setDnsCreateDryrunOpen(true)
      })
      .catch((err) => {
        if (err && err.code === 'unauthorized') {
          handleSessionExpired()
          return
        }
        setDnsCreateDryrunResults([
          { command: '(dryrun)', output: err.message || 'Error en dryrun' }
        ])
        setDnsCreateDryrunOpen(true)
      })
      .finally(() => setDnsCreateDryrunLoading(false))
  }

  const handleDnsCreateConfirm = () => {
    const payload = buildDnsCreatePayload()
    setDnsCreateLoading(true)
    createDnsRecord(payload)
      .then((resp) => {
        const msg = resp?.detail || 'DNS creada correctamente'
        setDnsCreateResult({
          status: 'success',
          message: msg,
          command: resp?.command,
          output: resp?.output
        })
        setDnsCreateConfirmOpen(false)
        resetDnsCreateForm()
      })
      .catch((err) => {
        if (err && err.code === 'unauthorized') {
          handleSessionExpired()
          return
        }
        setDnsCreateResult({
          status: 'error',
          message: err.message || 'No se pudo crear la DNS'
        })
        setDnsCreateConfirmOpen(false)
      })
      .finally(() => setDnsCreateLoading(false))
  }

  const handleIpAction = (row, action) => {
    if (action === 'reserve') {
      setReserveIp(row.ip || row.ip_address || '')
      setReserveLayer3(subnetModalLayer3 || row.layer3domain || '')
      setReservePool(subnetModalPool || row.pool || '')
      setReserveCreateDns(true)
      setReserveFqdn('')
      setReserveView('default')
      setReserveComment('')
      setReserveError('')
      setReserveSuccess('')
      setReserveSaving(false)
      setReserveModalOpen(true)
    } else if (action === 'release') {
      setReleaseIp(row.ip || row.ip_address || '')
      setReleasePool(subnetModalPool || row.pool || '')
      setReleaseError('')
      setReleaseSaving(false)
      setReleaseModalOpen(true)
    } else if (action === 'edit') {
      setEditIpValue(row.ip || row.ip_address || '')
      setEditPool(subnetModalPool || row.pool || '')
      setEditLayer3(subnetModalLayer3 || row.layer3domain || '')
      setEditDns(row.ptr_target || row.fqdn || '')
      setEditInitialDns(row.ptr_target || row.fqdn || '')
      setEditComment(row.comment || '')
      setEditInitialComment(row.comment || '')
      const viewValue = (row.dns_view || row.view || 'default').toLowerCase()
      const normalizedView =
        viewValue === 'internal/public' || viewValue === 'public/internal' ? 'both' : viewValue
      setEditView(normalizedView || 'default')
      setEditViewInitial(normalizedView || 'default')
      setEditDetectedViews(
        normalizedView && normalizedView !== 'default'
          ? normalizedView === 'both'
            ? ['internal', 'public']
            : [normalizedView]
          : []
      )
      setEditError('')
      setEditSaving(false)
      setEditModalOpen(true)
      const fqdnRaw = (row.ptr_target || row.fqdn || '').trim().toLowerCase()
      const isArsys = fqdnRaw.endsWith('.arsyscloud.tools.') || fqdnRaw.endsWith('.arsyscloud.tools')
      if (isArsys) {
        const fqdn = fqdnRaw.endsWith('.') ? fqdnRaw : `${fqdnRaw}.`
        fetchDnsView({ name: fqdn, layer3domain: subnetModalLayer3 || row.layer3domain || undefined })
          .then((resp) => {
            // Log auxiliar para depurar detección de vistas en edición
            console.warn('fetchDnsView result', fqdn, resp)
            const detected = (resp?.view || 'default').toLowerCase()
            const normalizedDetected =
              detected === 'internal/public' || detected === 'public/internal'
                ? 'both'
                : detected
            setEditView(normalizedDetected || 'default')
            setEditViewInitial(normalizedDetected || 'default')
            const respViews = Array.isArray(resp?.views)
              ? resp.views
              : detected && detected !== 'default'
              ? normalizedDetected === 'both'
                ? ['internal', 'public']
                : [normalizedDetected]
              : []
            setEditDetectedViews(respViews)
          })
          .catch(() => {})
      }
    }
  }

  const refreshSubnetModal = async () => {
    if (!subnetModalTitle || !subnetModalLayer3) return
    setSubnetModalLoading(true)
    setSubnetModalError('')
    try {
      const data = await listSubnetIps({
        subnet: subnetModalTitle,
        layer3domain: subnetModalLayer3,
        status: subnetModalStatus,
        limit: 256
      })
      setSubnetModalRows(Array.isArray(data) ? data : [])
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      setSubnetModalError(err.message || 'No se pudieron obtener las IPs de la subred')
    } finally {
      setSubnetModalLoading(false)
    }
  }

  const handleReserveSubmit = async () => {
    setReserveError('')
    setReserveSuccess('')

    if (!reservePool || !reserveIp) {
      setReserveError('Faltan datos de pool o IP para reservar.')
      return
    }

    const trimmedComment = reserveComment.trim()
    const viewMapping = {
      Interna: 'internal',
      'Pública': 'public',
      'Interna/Pública': 'both',
      default: 'default'
    }
    const payload = {
      pool: reservePool,
      ip: reserveIp,
      comment: trimmedComment || undefined,
      create_dns: reserveCreateDns
    }

    if (reserveCreateDns) {
      if (!reserveFqdn.trim()) {
        setReserveError('Debes indicar un FQDN para crear DNS.')
        return
      }
      payload.fqdn = reserveFqdn.trim()
      payload.view = viewMapping[reserveView] || reserveView || 'default'
      payload.layer3domain = reserveLayer3 || undefined
    }

    setReserveSaving(true)
    try {
      const response = await reserveIpRequest(payload)
      const message = response?.detail || 'IP reservada correctamente'
      setReserveSuccess(message)
      setPendingSubnetRefresh(true)
      setReserveModalOpen(false)
      setIpActionResult({
        status: 'success',
        message,
        ip: reserveIp,
        action: 'reserve'
      })
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      setReserveError(err.message || 'No se pudo reservar la IP')
    } finally {
      setReserveSaving(false)
    }
  }

  const handleReleaseSubmit = async () => {
    setReleaseError('')
    if (!releasePool || !releaseIp) {
      setReleaseError('Faltan datos de pool o IP para liberar.')
      return
    }
    setReleaseSaving(true)
    try {
      const response = await releaseIpRequest({
        pool: releasePool,
        ip: releaseIp
      })
      const message = response?.detail || 'IP liberada correctamente'
      setPendingSubnetRefresh(true)
      setReleaseModalOpen(false)
      setIpActionResult({
        status: 'success',
        message,
        ip: releaseIp,
        action: 'release'
      })
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      setPendingSubnetRefresh(false)
      setReleaseError(err.message || 'No se pudo liberar la IP')
      setIpActionResult({
        status: 'error',
        message: err.message || 'No se pudo liberar la IP',
        ip: releaseIp,
        action: 'release'
      })
      setReleaseModalOpen(false)
    } finally {
      setReleaseSaving(false)
    }
  }

  const handleEditSubmit = async () => {
    if (editDnsInvalid) {
      setEditError(editDnsInvalid)
      return
    }
    const trimmedDns = editDns.trim()
    const trimmedInitialDns = editInitialDns.trim()
    const trimmedComment = editComment
    const trimmedInitialComment = editInitialComment

    const changedDns = trimmedDns !== trimmedInitialDns
    const changedComment = trimmedComment !== trimmedInitialComment

    if (!changedDns && !changedComment) {
      setEditModalOpen(false)
      setIpActionResult({
        status: 'success',
        message: 'No hay cambios que guardar',
        ip: editIpValue,
        action: 'edit'
      })
      setPendingSubnetRefresh(false)
      return
    }

    if (!editPool || !editIpValue) {
      setEditError('Faltan datos de pool o IP para editar.')
      return
    }

    const viewMapping = {
      Interna: 'internal',
      'Pública': 'public',
      'Interna/Pública': 'both',
      default: 'default',
      internal: 'internal',
      public: 'public',
      both: 'both'
    }

    const payload = {
      pool: editPool,
      ip: editIpValue,
      dns: trimmedDns || undefined,
      old_dns: trimmedInitialDns || undefined,
      comment: trimmedComment,
      view: viewMapping[editView] || editView || 'default',
      old_view: viewMapping[editViewInitial] || editViewInitial || 'default',
      layer3domain: editLayer3 || undefined,
      changed_dns: changedDns,
      changed_comment: changedComment
    }

    setEditSaving(true)
    setEditError('')
    try {
      const response = await editIpRequest(payload)
      const message = response?.detail || 'IP actualizada correctamente'
      setEditModalOpen(false)
      setPendingSubnetRefresh(true)
      setIpActionResult({
        status: 'success',
        message,
        ip: editIpValue,
        action: 'edit'
      })
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      setEditError(err.message || 'No se pudo editar la IP')
    } finally {
      setEditSaving(false)
    }
  }

  const handleResultAccept = async () => {
    setIpActionResult(null)
    if (pendingSubnetRefresh && subnetModalOpen) {
      await refreshSubnetModal()
    }
    setPendingSubnetRefresh(false)
    setReleaseIp('')
    setReleasePool('')
    setReleaseError('')
    setReleaseSaving(false)
    setReleaseModalOpen(false)
    setEditModalOpen(false)
    setEditIpValue('')
    setEditDns('')
    setEditComment('')
    setEditError('')
    setEditSaving(false)
    setEditDetectedViews([])
      setActionResetNonce((n) => n + 1)
  }

  const handleGenerateCommands = () => {
    setCommandMessage('')
    if (importResolving) {
      setCommandMessage('Aún se están resolviendo las IPs, espera unos segundos.')
      return
    }
    if (!importRows.length) {
      setCommandMessage('No hay filas cargadas para generar comandos.')
      return
    }
    const lines = importRows
      .filter((row) => row && row.ip && row.pool && row.status !== 'error')
      .map((row) => {
        const commentRaw = (row.hostname || '').trim() || 'sin-hostname'
        const comment = commentRaw.replace(/"/g, '\\"')
        return `ndcli modify pool ${row.pool} mark ip ${row.ip} "comment:${comment}"`
      })

    if (!lines.length) {
      setCommandMessage('No hay filas válidas para generar comandos (revisa IP, Pool y estado).')
      return
    }

    const csvName = importFile?.name || 'hosts.csv'
    const baseName = csvName.toLowerCase().endsWith('.csv') ? csvName.slice(0, -4) : csvName
    const lowerBase = baseName.toLowerCase()
    const idx = lowerBase.indexOf('hosts')
    const stamped =
      idx !== -1
        ? `${baseName.slice(0, idx + 'hosts'.length)}_commands${baseName.slice(idx + 'hosts'.length)}`
        : `${baseName}_commands`
    const downloadName = `${stamped}.txt`

    const blob = new Blob([lines.join('\n')], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = downloadName
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleDryrun = async () => {
    if (importButtonsDisabled) return
    setImportDryrunError('')
    setImportExecuteError('')
    setImportExecuteResults([])
    setImportExecuteOpen(false)
    const candidates = importRows.filter(
      (row) =>
        row &&
        row.ip &&
        row.pool &&
        row.layer3domain &&
        !row.poolNeedsReview &&
        !row.layer3NeedsReview &&
        row.status !== 'error'
    )

    if (!candidates.length) {
      setImportDryrunError('No hay filas válidas para ejecutar dryrun.')
      return
    }

    const payload = {
      items: candidates.map((row) => ({
        ip: row.ip,
        pool: row.pool,
        layer3domain: row.layer3domain,
        hostname: row.hostname || ''
      }))
    }

    setImportDryrunLoading(true)
    try {
      const resp = await importDryrun(payload)
      const mapped = resp.map((item) => ({
        command: item.command || '',
        result:
          item.status === 'ok'
            ? { type: 'info', message: (item.output || '').trim() || 'OK' }
            : { type: 'error', message: (item.error || '').trim() || 'Error en dryrun' },
        ip: item.ip,
        pool: item.pool,
        layer3domain: item.layer3domain
      }))
      setImportDryrunResults(mapped)
      setImportConfirmOpen(false)
      setImportDryrunOpen(true)
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      setImportDryrunError(err.message || 'No se pudo ejecutar el dryrun')
    } finally {
      setImportDryrunLoading(false)
    }
  }

  const resetImportState = () => {
    setImportFile(null)
    setImportRows([])
    setImportResolving(false)
    setImportSearch('')
    setImportPageSize('10')
    setImportDryrunResults([])
    setImportDryrunOpen(false)
    setImportDryrunError('')
    setImportExecuteResults([])
    setImportExecuteOpen(false)
    setImportExecuteError('')
    setImportConfirmOpen(false)
    setCommandMessage('')
  }

  const handleExecuteImport = async () => {
    if (importButtonsDisabled) return
    setImportExecuteError('')
    setImportDryrunError('')
    setImportDryrunResults([])
    setImportDryrunOpen(false)

    const candidates = importRows.filter(
      (row) =>
        row &&
        row.ip &&
        row.pool &&
        row.layer3domain &&
        !row.poolNeedsReview &&
        !row.layer3NeedsReview &&
        row.status !== 'error'
    )

    if (!candidates.length) {
      setImportExecuteError('No hay filas válidas para importar.')
      return
    }

    const payload = {
      items: candidates.map((row) => ({
        ip: row.ip,
        pool: row.pool,
        layer3domain: row.layer3domain,
        hostname: row.hostname || ''
      }))
    }

    setImportExecuteLoading(true)
    try {
      const resp = await importExecute(payload)
      const mapped = resp.map((item) => ({
        ip: item.ip,
        pool: item.pool,
        layer3domain: item.layer3domain,
        action: item.action,
        detail: item.detail,
        status: item.status,
        existing_comment: item.existing_comment,
        command: item.command || '',
        output: item.output || ''
      }))
      setImportExecuteResults(mapped)
      setImportConfirmOpen(false)
      setImportExecuteOpen(true)
    } catch (err) {
      if (err && err.code === 'unauthorized') {
        handleSessionExpired()
        return
      }
      setImportExecuteError(err.message || 'No se pudo ejecutar la importación')
    } finally {
      setImportExecuteLoading(false)
    }
  }

  const handleFileChange = (file) => {
    setImportSearch('')
    setImportPageSize('10')
    setImportFile(file || null)
    if (!file) {
      setImportRows([])
      return
    }
    const reader = new FileReader()
    reader.onload = () => {
      const lines = (reader.result || '').toString().split(/\r?\n/).filter(Boolean)
      const parsed = lines.slice(1).map((line) => {
        const cols = line.split(',').map((x) => x?.trim())
        const ip = cols[0]
        const hostname = cols[1]
        return { ip, hostname }
      })
      const cleaned = parsed.filter((r) => r.ip)
      if (!cleaned.length) {
        setImportRows([])
        return
      }
      const placeholders = cleaned.map((r) => ({
        ip: r.ip,
        hostname: r.hostname,
        pool: 'Buscando…',
        layer3domain: 'Buscando…',
        poolNeedsReview: false,
        layer3NeedsReview: false,
        status: 'loading'
      }))
      setImportRows(placeholders)
      setImportResolving(true)
        importIpInfo({ items: cleaned })
          .then((resp) => {
            const merged = resp.map((item, idx) => {
              const resolvedIp = item.ip || cleaned[idx]?.ip || ''
              const resolvedHostname = item.hostname || cleaned[idx]?.hostname || ''
            const missingPool = !item.pool
            const missingLayer3 = !item.layer3domain
            const needsManualReview = missingPool && missingLayer3
            const poolValue = needsManualReview ? manualReviewLabel : item.pool || '—'
            const l3Value = needsManualReview
              ? manualReviewLabel
              : item.layer3domain || (item.status === 'ok' ? 'default' : '—')

            return {
              ip: resolvedIp,
              hostname: resolvedHostname,
              pool: poolValue,
              layer3domain: l3Value,
              status: needsManualReview ? 'error' : item.status,
              detail: item.detail,
              poolNeedsReview: needsManualReview,
              layer3NeedsReview: needsManualReview
            }
          })
          setImportRows(merged)
        })
        .catch((err) => {
          if (err && err.code === 'unauthorized') {
            handleSessionExpired()
            return
          }
          const fallback = cleaned.map((r) => ({
            ip: r.ip,
            hostname: r.hostname,
            pool: manualReviewLabel,
            layer3domain: manualReviewLabel,
            detail: err?.message || 'No se pudo resolver la IP',
            status: 'error',
            poolNeedsReview: true,
            layer3NeedsReview: true
          }))
          setImportRows(fallback)
        })
        .finally(() => setImportResolving(false))
    }
    reader.readAsText(file)
  }

  if (!auth) {
    return (
      <LoginScreen
        palette={palette}
        error={loginError}
        loggingIn={loggingIn}
        onSubmit={({ username, password }) => {
          if (!username || !password) {
            setLoginError('Introduce usuario y contraseña')
            return
          }
          setLoggingIn(true)
              loginRequest(username, password)
                .then((resp) => {
                  resetUiState()
                  setAuth(true)
                  setUserName(resp?.display_name || resp?.username || username)
                  setLoginError('')
                })
            .catch((err) => setLoginError(err.message))
            .finally(() => setLoggingIn(false))
        }}
      />
    )
  }

  const infoText =
    activeTab === 'consultas-acs'
      ? 'Las búsquedas de Pool, Subred e IP se realizan primero en el layer3domain por defecto y luego en los dominios ACS disponibles.'
      : activeTab === 'consultas-ionos'
        ? 'Estas búsquedas usan el layer3domain por defecto y se reintentan únicamente en los layer3domains de DIM que no pertenecen a ACS. Solo están disponibles las consultas por Subred e IP.'
        : ''
  const deviceInfo =
    isDeviceSearch &&
    'Las búsquedas de devices se realizan en los dominios ACS disponibles. Se mostrarán todas las IPs asociadas a ese device ya sea en el comment de la IP o en su DNS.'

  const isDnsArsyscloud =
    activeTab === 'consultas-acs' &&
    type === 'dns' &&
    q.trim().toLowerCase().includes('.arsyscloud.tools.')

  return (
    <div style={{ minHeight: '100vh', background: palette.bg, color: palette.text }}>
      <div style={{ ...containerStyle, paddingTop: '1.4rem', paddingBottom: '0.6rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '32px', fontFamily: '"Georgia","Times New Roman",serif' }}>Portal DIM</h1>
          <p style={{ margin: '0.25rem 0 0', color: palette.muted }}>Gestión de Pools, Subredes y DNS en DIM</p>
        </div>
        <div
          style={{
            marginLeft: 'auto',
            display: 'flex',
            alignItems: 'center',
            gap: '0.85rem',
            flexWrap: 'wrap',
            justifyContent: 'flex-end'
          }}
        >
          <div
            style={{
              display: 'inline-flex',
              gap: 8,
              padding: 4,
              border: `1px solid ${palette.border}`,
              borderRadius: 999,
              background: palette.card,
              boxShadow: theme === 'dark' ? 'inset 0 1px 0 rgba(255,255,255,0.05)' : 'none'
            }}
            role="group"
            aria-label="Seleccionar modo de visualización"
          >
            {[
              { key: 'light', label: 'Modo claro' },
              { key: 'dark', label: 'Modo oscuro' }
            ].map((opt) => {
              const active = theme === opt.key
              return (
                <button
                  key={opt.key}
                  type="button"
                  onClick={() => setTheme(opt.key)}
                  aria-pressed={active}
                  style={{
                    padding: '6px 14px',
                    border: 'none',
                    borderRadius: 999,
                    background: active ? palette.primary : 'transparent',
                    color: active ? '#fff' : palette.text,
                    fontWeight: 700,
                    cursor: 'pointer',
                    transition: 'background-color 0.2s ease, color 0.2s ease, transform 0.2s ease',
                    boxShadow: active ? '0 1px 4px rgba(0,0,0,0.25)' : 'none'
                  }}
                >
                  {opt.label}
                </button>
              )
            })}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontWeight: 700, color: palette.text }}>{userName || 'Usuario'}</span>
            <button
              type="button"
              onClick={() => {
                logoutRequest().finally(() => {
                  setAuth(false)
                  setUserName('')
                })
              }}
              style={{
                padding: '8px 16px',
                borderRadius: 10,
                border: `1px solid ${palette.primary}`,
                background: palette.primary,
                color: '#fff',
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'background-color 0.2s ease, transform 0.2s ease',
                boxShadow: '0 2px 6px rgba(0,0,0,0.25)'
              }}
            >
              Cerrar sesión
            </button>
          </div>
        </div>
      </div>

      <div style={{ ...containerStyle, paddingBottom: '2rem' }}>
        <div style={{ display: 'flex', gap: 6, marginBottom: 14 }}>
          {TABS.map((tab) => (
            <button
              key={tab.key}
              type="button"
              disabled={tab.disabled}
              onClick={() => setActiveTab(tab.key)}
              style={{
                padding: '9px 16px',
                borderRadius: 6,
                background: activeTab === tab.key ? palette.primary : '#0f1d35',
                color: activeTab === tab.key ? '#f5f7ff' : palette.muted,
                border: `1px solid ${activeTab === tab.key ? palette.primary : '#1b2c4a'}`,
                boxShadow: activeTab === tab.key ? '0 2px 6px rgba(0,0,0,0.35)' : 'inset 0 1px 0 rgba(255,255,255,0.03)',
                opacity: tab.disabled ? 0.5 : 1,
                cursor: tab.disabled ? 'not-allowed' : 'pointer',
                fontWeight: activeTab === tab.key ? 700 : 600,
                letterSpacing: '0.01em'
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div
          style={{
            background: palette.card,
            border: `1px solid ${palette.border}`,
            borderRadius: 10,
            padding: '14px 16px',
            marginBottom: 18,
            color: palette.muted
          }}
        >
          {isDeviceSearch ? (
            <div style={{ color: palette.muted }}>{deviceInfo}</div>
          ) : (
            <div>{infoText}</div>
          )}
        </div>

        {activeTab === 'gestion-dns' ? (
          <div
            style={{
              background: palette.card,
              border: `1px solid ${palette.border}`,
              borderRadius: 10,
              padding: '14px 16px'
            }}
          >
            <div style={{ marginBottom: 14 }}>
              <h3 style={{ margin: 0, color: palette.text }}>Gestión DNS</h3>
              <p style={{ margin: '6px 0 0', color: palette.muted }}>
                Selecciona la acción que necesites. Esta sección es independiente del resto del portal.
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
              {[
                { key: 'create-single', label: 'Crear entrada DNS' },
                { key: 'create-bulk', label: 'Crear DNS masivas' },
                { key: 'delete-single', label: 'Eliminar entrada DNS' },
                { key: 'delete-bulk', label: 'Eliminar DNS masivas' }
              ].map((opt) => (
                <button
                  key={opt.key}
                  type="button"
                  onClick={() => setDnsSectionAction(opt.key)}
                  style={{
                    padding: '10px 14px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: dnsSectionAction === opt.key ? palette.primary : palette.tableRow,
                    color: dnsSectionAction === opt.key ? '#fff' : palette.text,
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            {dnsSectionAction === 'create-single' ? (
              <form
                onSubmit={handleDnsCreateSubmit}
                style={{
                  display: 'grid',
                  gap: 12,
                  gridTemplateColumns: '1fr',
                  background: palette.tableRow,
                  border: `1px solid ${palette.border}`,
                  borderRadius: 10,
                  padding: '12px 14px'
                }}
              >
                <div style={{ color: palette.muted }}>
                  Desde esta pantalla se pueden crear entradas DNS únicas.
                </div>
                <div>
                  <div style={{ marginBottom: 6, color: palette.muted }}>FQDN</div>
                  <input
                    value={dnsCreateFqdn}
                    onChange={(e) => setDnsCreateFqdn(e.target.value)}
                    placeholder="host.ejemplo.lan."
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      borderRadius: 8,
                      border: `1px solid ${palette.border}`,
                      background: palette.card,
                      color: palette.text
                    }}
                  />
                  {dnsCreateFqdnInvalid ? (
                    <div style={{ marginTop: 6, color: palette.danger, fontSize: '0.9rem' }}>{dnsCreateFqdnInvalid}</div>
                  ) : null}
                </div>
                <div>
                  <div style={{ marginBottom: 6, color: palette.muted }}>IP</div>
                  <input
                    value={dnsCreateIp}
                    onChange={(e) => setDnsCreateIp(e.target.value)}
                    placeholder="10.0.0.1"
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      borderRadius: 8,
                      border: `1px solid ${palette.border}`,
                      background: palette.card,
                      color: palette.text
                    }}
                  />
                  {dnsCreateIpInvalid ? (
                    <div style={{ marginTop: 6, color: palette.danger, fontSize: '0.9rem' }}>{dnsCreateIpInvalid}</div>
                  ) : null}
                </div>
                {dnsCreateRequiresView ? (
                  <div>
                    <div style={{ marginBottom: 6, color: palette.muted }}>Vista</div>
                    <select
                      value={dnsCreateView}
                      onChange={(e) => setDnsCreateView(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '10px 12px',
                        borderRadius: 8,
                        border: `1px solid ${palette.border}`,
                        background: palette.card,
                        color: palette.text
                      }}
                    >
                      {dnsCreateViewOptions.map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : null}
                {dnsCreateError ? <div style={{ color: palette.danger }}>{dnsCreateError}</div> : null}
                {dnsCreateMessage ? <div style={{ color: palette.success }}>{dnsCreateMessage}</div> : null}
                <div>
                  <button
                    type="submit"
                    disabled={dnsCreateSubmitDisabled || dnsCreateLoading}
                    style={{
                      padding: '11px 16px',
                      borderRadius: 8,
                      border: 'none',
                      background: dnsCreateSubmitDisabled || dnsCreateLoading ? palette.border : palette.primary,
                      color: '#fff',
                      fontWeight: 700,
                      cursor: dnsCreateSubmitDisabled || dnsCreateLoading ? 'not-allowed' : 'pointer'
                    }}
                  >
                    {dnsCreateLoading ? 'Creando…' : 'Crear DNS'}
                  </button>
                </div>
              </form>
            ) : (
              <div style={{ color: palette.muted }}>Esta opción se habilitará en los siguientes pasos.</div>
            )}
          </div>
        ) : activeTab !== 'importacion-ips' ? (
          <>
            <form
              onSubmit={onSearch}
              style={{
                background: palette.card,
                border: `1px solid ${palette.border}`,
                borderRadius: 10,
                padding: '12px 14px',
                display: 'grid',
                gridTemplateColumns: isDnsArsyscloud ? '1.2fr 1.6fr 1fr auto' : '1.4fr 1.6fr auto',
                gap: 12,
                alignItems: 'end',
                marginBottom: 16
              }}
            >
              <div>
                <label style={{ color: palette.muted, display: 'block', marginBottom: 6 }}>Tipo de búsqueda</label>
                <select
                  value={type}
                  onChange={(e) => {
                    setType(e.target.value)
                    setQ('')
                    setRows([])
                    setPageSize(10)
                  }}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: palette.tableRow,
                    color: palette.text
                  }}
                >
                  {(activeTab === 'consultas-acs' ? SEARCH_TYPES_ACS : SEARCH_TYPES_IONOS).map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ color: palette.muted, display: 'block', marginBottom: 6 }}>Consulta</label>
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder={PLACEHOLDERS[type] || 'Valor'}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: palette.tableRow,
                    color: palette.text
                  }}
                />
                {dnsInlineError ? (
                  <div style={{ marginTop: 6, color: palette.danger, fontSize: '0.9rem' }}>
                    {dnsInlineError}
                  </div>
                ) : null}
                {(!dnsInlineError && subnetInlineError) ? (
                  <div style={{ marginTop: 6, color: palette.danger, fontSize: '0.9rem' }}>
                    {subnetInlineError}
                  </div>
                ) : null}
              </div>
              {isDnsArsyscloud ? (
                <div>
                  <label style={{ color: palette.muted, display: 'block', marginBottom: 6 }}>Vista</label>
                  <select
                    value={dnsView}
                    onChange={(e) => setDnsView(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      borderRadius: 8,
                      border: `1px solid ${palette.border}`,
                      background: palette.tableRow,
                      color: palette.text
                    }}
                  >
                    {['Interna', 'Pública', 'Interna/Pública'].map((opt) => (
                      <option key={opt} value={opt}>
                        {opt}
                      </option>
                    ))}
                  </select>
                </div>
              ) : null}
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  type="submit"
                  disabled={isSearchDisabled}
                  style={{
                    padding: '12px 18px',
                    borderRadius: 6,
                    border: 'none',
                    background: isSearchDisabled ? palette.border : palette.primary,
                    color: '#f6f8ff',
                    fontWeight: 700,
                    minWidth: 110,
                    cursor: isSearchDisabled ? 'not-allowed' : 'pointer',
                    boxShadow: isSearchDisabled ? 'none' : '0 3px 8px rgba(0,0,0,0.35)'
                  }}
                >
                  {loading ? 'Buscando…' : 'Buscar'}
                </button>
              </div>
            </form>

            {error && !dnsInlineError && !subnetInlineError ? (
              <div style={{ color: palette.danger, marginBottom: 12 }}>{error}</div>
            ) : null}

            <ResultsTable
              palette={palette}
              rows={visibleRows}
              totalRows={rows.length}
              loading={loading}
              pageSize={pageSize}
              onPageSizeChange={setPageSize}
              onSubnetAction={handleSubnetAction}
              searchType={type}
            />
          </>
        ) : (
          <div
            style={{
              background: palette.card,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: 18
            }}
          >
            <div style={{ marginBottom: 16, textAlign: 'center' }}>
              <p style={{ margin: 0, color: palette.muted, marginBottom: 12 }}>
                Selecciona un fichero CSV con las IPs a importar. El fichero se procesará en el siguiente paso.
              </p>
              <input
                type="file"
                accept=".csv"
                ref={fileInputRef}
                style={{ display: 'none' }}
                onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                style={{
                  border: 'none',
                  background: palette.primary,
                  color: '#fff',
                  padding: '10px 14px',
                  borderRadius: 8,
                  cursor: 'pointer'
                }}
              >
                Seleccionar CSV
              </button>
              {importFile ? (
                <div style={{ marginTop: 10, color: palette.muted }}>
                  Archivo seleccionado: <strong style={{ color: palette.text }}>{importFile.name}</strong>
                </div>
              ) : null}
            </div>

            {importRows.length ? (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
                  <h3 style={{ marginTop: 0, marginBottom: 0, color: palette.text }}>Datos importados</h3>
                  <input
                    value={importSearch}
                    onChange={(e) => setImportSearch(e.target.value)}
                    placeholder="Buscar en IP, Hostname, Pool o Layer3Domain"
                    style={{
                      marginLeft: 'auto',
                      padding: '10px 12px',
                      borderRadius: 8,
                      border: `1px solid ${palette.border}`,
                      background: palette.tableRow,
                      color: palette.text,
                      minWidth: 'min(320px, 100%)'
                    }}
                  />
                </div>
                <div style={{ borderRadius: 8, border: `1px solid ${palette.border}`, overflow: 'hidden' }}>
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', background: palette.tableRow }}>
                      <thead>
                        <tr style={{ background: palette.tableHeader }}>
                          {['IP', 'Hostname', 'Pool', 'Layer3Domain'].map((h) => (
                            <th key={h} style={{ textAlign: 'left', padding: '10px 12px', color: palette.text, fontWeight: 700 }}>
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {importDisplayedRows.length ? (
                          importDisplayedRows.map((r, idx) => (
                            <tr key={`${r.ip}-${idx}`} style={{ borderTop: `1px solid ${palette.border}` }}>
                              <td style={{ padding: '10px 12px' }}>{r.ip}</td>
                              <td style={{ padding: '10px 12px' }}>{r.hostname || '—'}</td>
                              <td
                                style={{
                                  padding: '10px 12px',
                                  color: r.poolNeedsReview ? palette.danger : palette.text
                                }}
                              >
                                {r.poolNeedsReview ? manualReviewLabel : r.pool || '—'}
                              </td>
                              <td
                                style={{
                                  padding: '10px 12px',
                                  color: r.layer3NeedsReview ? palette.danger : palette.text
                                }}
                              >
                                {r.layer3NeedsReview ? manualReviewLabel : r.layer3domain || 'default'}
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan={4} style={{ padding: '12px 12px', color: palette.muted }}>
                              Sin resultados
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 8,
                      padding: '10px 12px',
                      color: palette.muted,
                      borderTop: `1px solid ${palette.border}`
                    }}
                  >
                    <span>
                      Mostrando {importDisplayedRows.length} de {importRows.length} resultados
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>Mostrar</span>
                      <select
                        value={importPageSize}
                        onChange={(e) => setImportPageSize(e.target.value)}
                        style={{
                          padding: '6px 10px',
                          borderRadius: 8,
                          border: `1px solid ${palette.border}`,
                          background: palette.tableRow,
                          color: palette.text
                        }}
                      >
                        {['10', '50', '100', '150', 'all'].map((opt) => (
                          <option key={opt} value={opt}>
                            {opt === 'all' ? 'Todas' : opt}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 12, marginTop: 14, alignItems: 'center', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    onClick={handleGenerateCommands}
                    style={{
                      padding: '10px 14px',
                      background: palette.primary,
                      border: 'none',
                      color: '#fff',
                      borderRadius: 8,
                      cursor: importButtonsDisabled ? 'not-allowed' : 'pointer',
                      opacity: importButtonsDisabled ? 0.6 : 1
                    }}
                    disabled={importButtonsDisabled}
                  >
                    Generar comandos
                  </button>
                  <button
                    type="button"
                  onClick={() => {
                    setImportDryrunError('')
                    setImportExecuteError('')
                    setImportConfirmOpen(true)
                  }}
                    style={{
                      padding: '10px 14px',
                      background: palette.primary,
                      border: 'none',
                      color: '#fff',
                      borderRadius: 8,
                      cursor: importButtonsDisabled ? 'not-allowed' : 'pointer',
                      opacity: importButtonsDisabled ? 0.6 : 1
                    }}
                    disabled={importButtonsDisabled}
                  >
                    Importar IPs
                  </button>
                  {commandMessage ? (
                    <span style={{ color: palette.muted, alignSelf: 'center' }}>{commandMessage}</span>
                  ) : null}
                </div>
              </>
            ) : (
              <p style={{ color: palette.muted, margin: 0 }}>Aún no se ha seleccionado ningún fichero.</p>
            )}
          </div>
        )}
      </div>

      {sessionExpired ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2500,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.5rem',
              width: 'min(420px, 100%)',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)',
              textAlign: 'center'
            }}
          >
            <h3 style={{ marginTop: 0, marginBottom: 10, fontSize: '1.3rem' }}>Sesión expirada</h3>
            <p style={{ marginTop: 0, marginBottom: 20, color: palette.muted }}>
              Tu sesión ha expirado. Cierra este aviso y vuelve a iniciar sesión.
            </p>
            <button
              type="button"
              onClick={() => {
                setSessionExpired(false)
                setAuth(false)
                setUserName('')
                setRows([])
                setQ('')
                setError('')
              }}
              style={{
                padding: '10px 16px',
                borderRadius: 10,
                border: 'none',
                background: palette.primary,
                color: '#fff',
                fontWeight: 700,
                cursor: 'pointer',
                minWidth: 120
              }}
            >
              Cerrar
            </button>
          </div>
        </div>
      ) : null}

      {dnsCreateConfirmOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2600,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.2rem',
              width: 'min(520px, 95%)',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 10 }}>Confirmar creación DNS</div>
            <div style={{ color: palette.muted, marginBottom: 12 }}>
              FQDN: <strong style={{ color: palette.text }}>{dnsCreateFqdn.trim() || '—'}</strong>
              <br />
              IP: <strong style={{ color: palette.text }}>{dnsCreateIp.trim() || '—'}</strong>
              <br />
              Vista: <strong style={{ color: palette.text }}>{dnsCreateRequiresView ? dnsCreateView : 'default'}</strong>
            </div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={resetDnsCreateForm}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: `1px solid ${palette.border}`,
                  background: 'transparent',
                  color: palette.text,
                  cursor: 'pointer'
                }}
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleDnsCreateDryrun}
                disabled={dnsCreateDryrunLoading}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: `1px solid ${palette.border}`,
                  background: palette.tableRow,
                  color: palette.text,
                  cursor: dnsCreateDryrunLoading ? 'wait' : 'pointer'
                }}
              >
                {dnsCreateDryrunLoading ? 'Dryrun…' : 'Dryrun'}
              </button>
              <button
                type="button"
                onClick={handleDnsCreateConfirm}
                disabled={dnsCreateLoading}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: 'none',
                  background: dnsCreateLoading ? palette.border : palette.primary,
                  color: '#fff',
                  fontWeight: 700,
                  cursor: dnsCreateLoading ? 'wait' : 'pointer',
                  minWidth: 120
                }}
              >
                {dnsCreateLoading ? 'Creando…' : 'Confirmar'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {dnsCreateDryrunOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2600,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.2rem',
              width: 'min(900px, 95%)',
              maxHeight: '80vh',
              overflow: 'hidden',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 12 }}>Resultado dryrun DNS</div>
            <div
              style={{
                border: `1px solid ${palette.border}`,
                borderRadius: 10,
                maxHeight: '60vh',
                overflowY: 'auto',
                background: palette.tableRow
              }}
            >
              {dnsCreateDryrunResults.length ? (
                dnsCreateDryrunResults.map((item, idx) => (
                  <div
                    key={idx}
                    style={{
                      borderBottom: idx === dnsCreateDryrunResults.length - 1 ? 'none' : `1px solid ${palette.border}`,
                      padding: '10px 12px'
                    }}
                  >
                    <div style={{ color: palette.muted, marginBottom: 6, fontWeight: 600 }}>
                      {item.command || '—'}
                    </div>
                    <pre
                      style={{
                        margin: 0,
                        whiteSpace: 'pre-wrap',
                        background: 'transparent',
                        color: palette.text,
                        fontSize: '0.95rem'
                      }}
                    >
                      {item.output || '—'}
                    </pre>
                  </div>
                ))
              ) : (
                <div style={{ padding: '12px 14px', color: palette.muted }}>No hay resultados.</div>
              )}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12, gap: 10 }}>
              <button
                type="button"
                onClick={() => setDnsCreateDryrunOpen(false)}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: 'none',
                  background: palette.primary,
                  color: '#fff',
                  fontWeight: 700,
                  cursor: 'pointer',
                  minWidth: 110
                }}
              >
                Cerrar
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {dnsCreateResult ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1.5rem',
            zIndex: 2800
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 14,
              padding: '1.75rem',
              width: 'min(520px, 95%)',
              textAlign: 'center',
              boxShadow: '0 24px 64px rgba(0,0,0,0.45)'
            }}
          >
            <h3 style={{ marginTop: 0, marginBottom: 10, fontSize: '1.25rem' }}>Resultado creación DNS</h3>
            <p
              style={{
                margin: '0 0 18px',
                color: dnsCreateResult.status === 'error' ? palette.danger : palette.muted,
                fontWeight: dnsCreateResult.status === 'error' ? 700 : 400
              }}
            >
              {dnsCreateResult.message || 'Operación completada'}
            </p>
            {dnsCreateResult.command ? (
              <div style={{ marginBottom: 12, color: palette.text, wordBreak: 'break-word' }}>{dnsCreateResult.command}</div>
            ) : null}
            {dnsCreateResult.output ? (
              <pre style={{ textAlign: 'left', whiteSpace: 'pre-wrap', margin: '0 0 12px', color: palette.text }}>
                {dnsCreateResult.output}
              </pre>
            ) : null}
            <button
              type="button"
              onClick={() => setDnsCreateResult(null)}
              style={{
                padding: '12px 18px',
                borderRadius: 10,
                border: 'none',
                background: palette.primary,
                color: '#fff',
                fontWeight: 700,
                cursor: 'pointer',
                minWidth: 140,
                boxShadow: '0 4px 10px rgba(0,0,0,0.35)'
              }}
            >
              Aceptar
            </button>
          </div>
        </div>
      ) : null}
      {importConfirmOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2550,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.4rem',
              width: 'min(620px, 95%)',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 10 }}>
              Confirmar importación
            </div>
            <div style={{ color: palette.muted, marginBottom: 18 }}>
              ¿Estás seguro de importar estas IPs en DIM?
            </div>
            {importDryrunError ? (
              <div style={{ color: palette.danger, marginBottom: 10 }}>{importDryrunError}</div>
            ) : null}
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setImportConfirmOpen(false)}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: `1px solid ${palette.border}`,
                  background: 'transparent',
                  color: palette.text,
                  cursor: 'pointer'
                }}
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleDryrun}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: `1px solid ${palette.border}`,
                  background: palette.tableRow,
                  color: palette.text,
                  cursor: importDryrunLoading ? 'wait' : 'pointer',
                  opacity: importDryrunLoading ? 0.7 : 1
                }}
                disabled={importDryrunLoading}
              >
                Dryrun
              </button>
              <button
                type="button"
                onClick={handleExecuteImport}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: 'none',
                  background: palette.primary,
                  color: '#fff',
                  fontWeight: 700,
                  cursor: importExecuteLoading ? 'wait' : 'pointer',
                  minWidth: 120
                }}
                disabled={importExecuteLoading}
              >
                {importExecuteLoading ? 'Importando…' : 'Confirmar'}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {importExecuteError ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2590,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.2rem',
              width: 'min(520px, 95%)',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ fontWeight: 700, marginBottom: 10 }}>Error al importar</div>
            <div style={{ color: palette.danger, marginBottom: 14 }}>{importExecuteError}</div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setImportExecuteError('')}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: 'none',
                  background: palette.primary,
                  color: '#fff',
                  fontWeight: 700,
                  cursor: 'pointer',
                  minWidth: 100
                }}
              >
                Cerrar
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {importDryrunOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2600,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.2rem',
              width: 'min(1400px, 97%)',
              maxHeight: '85vh',
              overflow: 'hidden',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 10 }}>
              Resultado dryrun
            </div>
            <div
              style={{
                border: `1px solid ${palette.border}`,
                borderRadius: 10,
                maxHeight: '60vh',
                overflowY: 'auto',
                background: palette.tableRow
              }}
            >
              {importDryrunResults.length ? (
                importDryrunResults.map((item, idx) => (
                  <div
                    key={idx}
                    style={{
                      borderBottom: idx === importDryrunResults.length - 1 ? 'none' : `1px solid ${palette.border}`,
                      padding: '10px 12px'
                    }}
                  >
                    <div style={{ color: palette.muted, marginBottom: 6, fontWeight: 600 }}>
                      {item.command}
                    </div>
                    <pre
                      style={{
                        margin: 0,
                        whiteSpace: 'pre-wrap',
                        background: 'transparent',
                        color: item.result.type === 'error' ? palette.danger : palette.text,
                        fontSize: '0.95rem'
                      }}
                    >
                      {item.result.message}
                    </pre>
                  </div>
                ))
              ) : (
                <div style={{ padding: '12px 14px', color: palette.muted }}>No hay resultados.</div>
              )}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
              <button
                type="button"
                onClick={() => setImportDryrunOpen(false)}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: 'none',
                  background: palette.primary,
                  color: '#fff',
                  fontWeight: 700,
                  cursor: 'pointer',
                  minWidth: 110
                }}
              >
                Cerrar
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {importExecuteOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2600,
            padding: '1.5rem'
          }}
          >
            <div
              style={{
                background: palette.card,
                color: palette.text,
                border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.2rem',
              width: 'min(900px, 95%)',
              maxHeight: '80vh',
              overflow: 'hidden',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 12 }}>Resultado importación</div>
            <div style={{ border: `1px solid ${palette.border}`, borderRadius: 10, overflow: 'hidden' }}>
              <div style={{ overflowX: 'auto', maxHeight: '60vh' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', background: palette.tableRow }}>
                  <thead>
                    <tr style={{ background: palette.tableHeader }}>
                      {['IP', 'Acción', 'Detalle', 'Comando ejecutado', 'Resultado'].map((h) => (
                        <th
                          key={h}
                          style={{ textAlign: 'left', padding: '10px 12px', color: palette.text, fontWeight: 700 }}
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                    <tbody>
                      {importExecuteResults.length ? (
                      importExecuteResults.map((item, idx) => {
                        const actionLabel =
                          item.action === 'executed'
                            ? 'Ejecutado'
                            : item.action === 'skipped'
                                ? 'Omitido'
                                : 'Error'
                        const actionColor =
                          item.action === 'executed'
                            ? palette.success
                            : item.action === 'skipped'
                              ? palette.muted
                              : palette.danger
                        const detail = item.detail || '—'
                        const output =
                          item.action === 'skipped'
                            ? '--'
                            : (item.output || '').trim() || (item.status || '') || '—'
                        return (
                          <tr key={`${item.ip}-${idx}`} style={{ borderTop: `1px solid ${palette.border}` }}>
                            <td style={{ padding: '10px 12px' }}>{item.ip || '—'}</td>
                            <td style={{ padding: '10px 12px', color: actionColor, fontWeight: 700 }}>{actionLabel}</td>
                            <td style={{ padding: '10px 12px', whiteSpace: 'pre-wrap' }}>{detail}</td>
                            <td style={{ padding: '10px 12px', whiteSpace: 'pre-wrap', color: palette.text }}>
                              {item.command || '—'}
                            </td>
                            <td style={{ padding: '10px 12px', whiteSpace: 'pre-wrap' }}>{output || '—'}</td>
                          </tr>
                        )
                      })
                    ) : (
                      <tr>
                        <td colSpan={7} style={{ padding: '12px 14px', color: palette.muted }}>
                          No hay resultados.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
              <button
                type="button"
                onClick={resetImportState}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: 'none',
                  background: palette.primary,
                  color: '#fff',
                  fontWeight: 700,
                  cursor: 'pointer',
                  minWidth: 110
                }}
              >
                Cerrar
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {reserveModalOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2600,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.4rem',
              width: 'min(520px, 95%)',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>Reserva IP: {reserveIp || '—'}</div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <div style={{ marginBottom: 6, color: palette.muted }}>Crear DNS</div>
                <div style={{ display: 'flex', gap: 14 }}>
                  {['Si', 'No'].map((opt) => {
                    const val = opt === 'Si'
                    return (
                      <label key={opt} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                        <input
                          type="radio"
                          name="reserve-create-dns"
                          checked={reserveCreateDns === val}
                          onChange={() => setReserveCreateDns(val)}
                        />
                        <span>{opt}</span>
                      </label>
                    )
                  })}
                </div>
              </div>

              {reserveCreateDns ? (
                <>
                  <div>
                    <div style={{ marginBottom: 6, color: palette.muted, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>Entrada DNS</span>
                      <span style={{ color: '#d75f5f' }}>*</span>
                    </div>
                    <input
                      value={reserveFqdn}
                      onChange={(e) => setReserveFqdn(e.target.value)}
                      placeholder="host.ejemplo.lan."
                      style={{
                        width: '100%',
                        padding: '10px 12px',
                        borderRadius: 8,
                        border: `1px solid ${palette.border}`,
                        background: palette.tableRow,
                        color: palette.text
                      }}
                    />
                    {isReserveFqdnInvalid ? (
                      <div style={{ marginTop: 6, color: palette.danger, fontSize: '0.92rem' }}>{isReserveFqdnInvalid}</div>
                    ) : null}
                  </div>

                  <div>
                    <div style={{ marginBottom: 6, color: palette.muted, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>Vista</span>
                      <span style={{ color: '#d75f5f' }}>*</span>
                    </div>
                    <select
                      value={reserveView}
                      onChange={(e) => setReserveView(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '10px 12px',
                        borderRadius: 8,
                        border: `1px solid ${palette.border}`,
                        background: palette.tableRow,
                        color: palette.text
                      }}
                    >
                      {reserveViews.map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  </div>
                </>
              ) : null}

              <div>
                <div style={{ marginBottom: 6, color: palette.muted }}>Comentario</div>
                <input
                  value={reserveComment}
                  onChange={(e) => setReserveComment(e.target.value)}
                  placeholder="Comentario (opcional)"
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: palette.tableRow,
                    color: palette.text
                  }}
                />
              </div>

              {reserveCreateDns ? (
                <div style={{ color: '#d75f5f', fontSize: '0.9rem' }}>* Campo obligatorio</div>
              ) : null}

              {reserveError ? <div style={{ color: palette.danger }}>{reserveError}</div> : null}
              {reserveSuccess ? <div style={{ color: palette.success }}>{reserveSuccess}</div> : null}

              <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
                <button
                  type="button"
                  disabled={
                    reserveSaving ||
                    reserveCreateDns &&
                    (!!isReserveFqdnInvalid || !reserveFqdn.trim() || !reserveView)
                  }
                  onClick={handleReserveSubmit}
                  style={{
                    padding: '10px 16px',
                    borderRadius: 8,
                    border: 'none',
                    background:
                      reserveSaving ||
                      (reserveCreateDns && (!!isReserveFqdnInvalid || !reserveFqdn.trim() || !reserveView))
                        ? palette.border
                        : palette.primary,
                    color: '#fff',
                    fontWeight: 700,
                    cursor:
                      reserveSaving ||
                      (reserveCreateDns && (!!isReserveFqdnInvalid || !reserveFqdn.trim() || !reserveView))
                        ? 'not-allowed'
                        : 'pointer',
                    boxShadow:
                      reserveSaving ||
                      (reserveCreateDns && (!!isReserveFqdnInvalid || !reserveFqdn.trim() || !reserveView))
                        ? 'none'
                        : '0 3px 8px rgba(0,0,0,0.35)'
                  }}
                >
                  {reserveSaving ? 'Reservando…' : 'Reservar IP'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setReserveModalOpen(false)
                    setReserveError('')
                    setReserveSuccess('')
                    setReserveSaving(false)
                    setReserveComment('')
                    setReserveFqdn('')
                    setReserveIp('')
                    setReservePool('')
                    setPendingSubnetRefresh(false)
                    setActionResetNonce((n) => n + 1)
                  }}
                  style={{
                    padding: '10px 16px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: 'transparent',
                    color: palette.text,
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Cancelar
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {subnetModalOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.45)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'flex-start',
            paddingTop: '4rem',
            zIndex: 2000
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              width: 'min(1100px, 95%)',
              maxHeight: '80vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 18px 48px rgba(0,0,0,0.45)',
              overflow: 'hidden'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', padding: '18px 20px', borderBottom: `1px solid ${palette.border}` }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: '18px' }}>IPs de {subnetModalTitle}</div>
                <div style={{ color: palette.muted, marginTop: 4 }}>
                  Layer3Domain: <strong style={{ color: palette.text }}>{subnetModalLayer3 || '—'}</strong>
                </div>
                <div style={{ color: palette.muted, marginTop: 2 }}>
                  Pool: <strong style={{ color: palette.text }}>{subnetModalPool || '—'}</strong>
                </div>
              </div>
              <div style={{ marginLeft: 'auto' }}>
                <button
                  type="button"
                  onClick={() => {
                    setSubnetModalOpen(false)
                    setSubnetModalRows([])
                  }}
                  style={{
                    background: 'transparent',
                    border: `1px solid ${palette.border}`,
                    color: palette.text,
                    borderRadius: 8,
                    padding: '8px 12px',
                    cursor: 'pointer'
                  }}
                >
                  Cerrar
                </button>
              </div>
            </div>

            <div style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
              <input
                value={subnetSearch}
                onChange={(e) => setSubnetSearch(e.target.value)}
                placeholder="Buscar en IP, estado, DNS o comentario"
                style={{
                  flex: 1,
                  padding: '10px 12px',
                  borderRadius: 8,
                  border: `1px solid ${palette.border}`,
                  background: palette.tableRow,
                  color: palette.text
                }}
              />
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: palette.muted }}>
                <span>Mostrar</span>
                <select
                  value={subnetPageSize}
                  onChange={(e) => setSubnetPageSize(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: palette.tableRow,
                    color: palette.text
                  }}
                >
                  {['10', '50', '100', 'all'].map((opt) => (
                    <option key={opt} value={opt}>
                      {opt === 'all' ? 'Todas' : opt}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {subnetModalError ? (
              <div style={{ color: palette.danger, padding: '0 16px 12px' }}>{subnetModalError}</div>
            ) : null}

            <div style={{ flex: 1, overflow: 'auto', padding: '0 16px 16px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ background: palette.tableHeader }}>
                    {['IP', 'Estado', 'DNS', 'Vista', 'Comentario', 'Acciones'].map((h) => (
                      <th
                        key={h}
                        style={{
                          textAlign: 'left',
                          padding: '12px 14px',
                          color: palette.text,
                          borderBottom: `1px solid ${palette.border}`
                        }}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {subnetModalLoading ? (
                    <tr>
                      <td colSpan={6} style={{ padding: '12px 12px', color: palette.muted }}>
                        Cargando IPs…
                      </td>
                    </tr>
                  ) : subnetFilteredRows.length ? (
                subnetFilteredRows.map((row, idx) => (
                    <tr key={`${row.ip}-${idx}`} style={{ borderTop: `1px solid ${palette.border}`, background: palette.tableRow }}>
                      <td style={{ padding: '10px 12px' }}>{row.ip || '—'}</td>
                      <td style={{ padding: '10px 12px' }}>{row.status || '—'}</td>
                      <td style={{ padding: '10px 12px' }}>{row.ptr_target || '—'}</td>
                      <td style={{ padding: '10px 12px' }}>
                        {(() => {
                          const dns = (row.ptr_target || '').trim().toLowerCase()
                          if (!dns) return '—'
                          const isArsys = dns.endsWith('.arsyscloud.tools.') || dns.endsWith('.arsyscloud.tools')
                          if (!isArsys) return 'Default'
                          const viewRaw = (row.dns_view || '').toLowerCase()
                          const hasInternal = viewRaw.includes('internal')
                          const hasPublic = viewRaw.includes('public')
                          if (hasInternal && hasPublic) return 'Interna/Pública'
                          if (hasInternal) return 'Interna'
                          if (hasPublic) return 'Pública'
                          return '—'
                        })()}
                      </td>
                      <td style={{ padding: '10px 12px' }}>{row.comment || '—'}</td>
                      <td style={{ padding: '10px 12px' }}>
                          <select
                            key={`actions-${idx}-${actionResetNonce}`}
                            defaultValue="select"
                            style={{
                              padding: '8px 10px',
                              borderRadius: 8,
                              border: `1px solid ${palette.border}`,
                              background: palette.tableRow,
                            color: palette.text
                          }}
                          onChange={(e) => {
                            const val = e.target.value
                            if (val === 'select') return
                            e.target.value = 'select'
                            setActionResetNonce((n) => n + 1)
                            handleIpAction(row, val)
                          }}
                        >
                          <option value="select">Selecciona</option>
                          {((row.status || '').toLowerCase() === 'available' ||
                            (row.status || '').toLowerCase() === 'free') && <option value="reserve">Reservar</option>}
                          {(row.status || '').toLowerCase() !== 'available' && (row.status || '').toLowerCase() !== 'free' ? (
                              <>
                                <option value="release">Liberar</option>
                                <option value="edit">Editar</option>
                              </>
                            ) : null}
                          </select>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} style={{ padding: '12px 12px', color: palette.muted }}>
                        Sin IPs para esta subred
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div style={{ padding: '10px 16px', color: palette.muted, display: 'flex', justifyContent: 'space-between' }}>
              <span>
                Mostrando {subnetFilteredRows.length} de {subnetModalRows.length} resultados
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span>Mostrar</span>
                <select
                  value={subnetPageSize}
                  onChange={(e) => setSubnetPageSize(e.target.value)}
                  style={{
                    padding: '6px 10px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: palette.tableRow,
                    color: palette.text
                  }}
                >
                  {['10', '50', '100', 'all'].map((opt) => (
                    <option key={opt} value={opt}>
                      {opt === 'all' ? 'Todas' : opt}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {editModalOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2600,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.4rem',
              width: 'min(520px, 95%)',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>Editar IP: {editIpValue || '—'}</div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <div style={{ marginBottom: 6, color: palette.muted }}>Entrada DNS</div>
                <input
                  value={editDns}
                  onChange={(e) => setEditDns(e.target.value)}
                  placeholder="host.ejemplo.lan."
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: palette.tableRow,
                    color: palette.text
                  }}
                />
                {editRequiresView ? (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ marginBottom: 6, color: palette.muted }}>Vista</div>
                    <select
                      value={editView}
                      onChange={(e) => setEditView(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '10px 12px',
                        borderRadius: 8,
                        border: `1px solid ${palette.border}`,
                        background: palette.tableRow,
                        color: palette.text
                      }}
                    >
                      {editViewOptions.map((opt) => (
                        <option key={opt.value} value={opt.value} disabled={opt.disabled}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : (
                  <div style={{ marginTop: 6, color: palette.muted, fontSize: '0.9rem' }}>
                    Vista: <strong style={{ color: palette.text }}>{editView || 'default'}</strong>
                  </div>
                )}
                {editDnsInvalid ? (
                  <div style={{ marginTop: 6, color: palette.danger, fontSize: '0.9rem' }}>
                    {editDnsInvalid}
                  </div>
                ) : null}
              </div>
              <div>
                <div style={{ marginBottom: 6, color: palette.muted }}>Comentario</div>
                <input
                  value={editComment}
                  onChange={(e) => setEditComment(e.target.value)}
                  placeholder="Comentario"
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: palette.tableRow,
                    color: palette.text
                  }}
                />
              </div>
              {editError ? <div style={{ color: palette.danger }}>{editError}</div> : null}
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  type="button"
                  onClick={handleEditSubmit}
                  disabled={editSaving || !!editDnsInvalid}
                  style={{
                    padding: '10px 16px',
                    borderRadius: 8,
                    border: 'none',
                    background: editSaving || editDnsInvalid ? palette.border : palette.primary,
                    color: '#fff',
                    fontWeight: 700,
                    cursor: editSaving || editDnsInvalid ? 'not-allowed' : 'pointer',
                    minWidth: 120,
                    boxShadow: editSaving || editDnsInvalid ? 'none' : '0 3px 8px rgba(0,0,0,0.35)'
                  }}
                >
                  {editSaving ? 'Guardando…' : 'Guardar IP'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setEditModalOpen(false)
                    setEditError('')
                    setEditSaving(false)
                    setEditDns('')
                    setEditComment('')
                  }}
                  style={{
                    padding: '10px 16px',
                    borderRadius: 8,
                    border: `1px solid ${palette.border}`,
                    background: 'transparent',
                    color: palette.text,
                    fontWeight: 600,
                    cursor: 'pointer',
                    minWidth: 120
                  }}
                >
                  Cancelar
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      {releaseModalOpen ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 2600,
            padding: '1.5rem'
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 12,
              padding: '1.4rem',
              width: 'min(500px, 95%)',
              boxShadow: '0 20px 48px rgba(0,0,0,0.45)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>Liberación IP: {releaseIp || '—'}</div>
            </div>
            {releaseError ? <div style={{ color: palette.danger, marginBottom: 10 }}>{releaseError}</div> : null}
            <p style={{ marginTop: 0, marginBottom: 18, color: palette.muted }}>
              Confirma si deseas liberar la IP seleccionada. Esta acción ejecutará el comando ndcli correspondiente.
            </p>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-start' }}>
              <button
                type="button"
                onClick={handleReleaseSubmit}
                disabled={releaseSaving}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: 'none',
                  background: releaseSaving ? palette.border : palette.primary,
                  color: '#fff',
                  fontWeight: 700,
                  cursor: releaseSaving ? 'not-allowed' : 'pointer',
                  minWidth: 120,
                  boxShadow: releaseSaving ? 'none' : '0 3px 8px rgba(0,0,0,0.35)'
                }}
              >
                {releaseSaving ? 'Liberando…' : 'Liberar IP'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setReleaseModalOpen(false)
                  setReleaseError('')
                  setReleaseSaving(false)
                  setActionResetNonce((n) => n + 1)
                }}
                style={{
                  padding: '10px 16px',
                  borderRadius: 8,
                  border: `1px solid ${palette.border}`,
                  background: 'transparent',
                  color: palette.text,
                  fontWeight: 600,
                  cursor: 'pointer',
                  minWidth: 120
                }}
              >
                Cancelar
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {ipActionResult ? (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1.5rem',
            zIndex: 2800
          }}
        >
          <div
            style={{
              background: palette.card,
              color: palette.text,
              border: `1px solid ${palette.border}`,
              borderRadius: 14,
              padding: '1.75rem',
              width: 'min(520px, 95%)',
              textAlign: 'center',
              boxShadow: '0 24px 64px rgba(0,0,0,0.45)'
            }}
          >
            <h3 style={{ marginTop: 0, marginBottom: 10, fontSize: '1.25rem' }}>Resultado de la operación</h3>
            <p
              style={{
                margin: '0 0 18px',
                color: ipActionResult.status === 'error' ? palette.danger : palette.muted,
                fontWeight: ipActionResult.status === 'error' ? 700 : 400
              }}
            >
              {ipActionResult.message || 'Operación completada'}
            </p>
            {ipActionResult.ip ? (
              <div style={{ marginBottom: 18, color: palette.text, fontWeight: 700 }}>IP: {ipActionResult.ip}</div>
            ) : null}
            <button
              type="button"
              onClick={handleResultAccept}
              style={{
                padding: '12px 18px',
                borderRadius: 10,
                border: 'none',
                background: palette.primary,
                color: '#fff',
                fontWeight: 700,
                cursor: 'pointer',
                minWidth: 140,
                boxShadow: '0 4px 10px rgba(0,0,0,0.35)'
              }}
            >
              Aceptar
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
