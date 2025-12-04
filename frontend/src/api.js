export async function getLayer3domains() {
  const r = await fetch('/api/layer3domains')
  if (!r.ok) throw new Error('No se pudieron cargar L3Ds')
  return (await r.json()).items
}

export async function fetchSession() {
  const r = await fetch('/api/auth/session', { credentials: 'include' })
  if (r.status === 401) {
    const err = new Error('No autenticado')
    // Señalamos a la UI el estado de sesión expirada
    err.code = 'unauthorized'
    throw err
  }
  if (!r.ok) throw new Error('Error obteniendo sesión')
  return await r.json()
}

export async function doSearch(params) {
  const sp = new URLSearchParams(params)
  const r = await fetch(`/api/search?${sp.toString()}`, { credentials: 'include' })
  if (!r.ok) {
    let detail = 'Error en la búsqueda'
    try {
      const errBody = await r.json()
      if (errBody?.detail) detail = errBody.detail
    } catch (_) {}
    const err = toApiError(r, detail)
    err.message = detail
    throw err
  }
  return await r.json()
}

export async function loginRequest(username, password) {
  const r = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username, password })
  })
  if (r.status === 401) {
    const err = await r.json().catch(() => ({}))
    throw new Error(err.detail || 'Credenciales inválidas')
  }
  if (!r.ok) {
    const err = await r.json().catch(() => ({}))
    throw new Error(err.detail || 'No se pudo iniciar sesión')
  }
  return await r.json() // { username, display_name? }
}

export async function logoutRequest() {
  await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' })
}

function toApiError(r, fallbackMessage = 'Error en la solicitud') {
  const error = new Error(fallbackMessage)
  if (r.status === 401) {
    error.code = 'unauthorized'
  }
  return error
}

async function postJson(url, body, fallbackMessage) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(body)
  })
  if (!r.ok) {
    let detail = fallbackMessage
    try {
      const data = await r.json()
      if (data?.detail) detail = data.detail
    } catch (_) {}
    const err = toApiError(r, detail)
    err.message = detail
    throw err
  }
  return r.json()
}

export async function listSubnetIps({ subnet, layer3domain, status = 'all', limit }) {
  return postJson('/api/subnet/ips', { subnet, layer3domain, status, limit }, 'No se pudieron obtener las IPs')
}

export async function reserveIp(payload) {
  return postJson('/api/ip/reserve', payload, 'No se pudo reservar la IP')
}

export async function releaseIp(payload) {
  return postJson('/api/ip/release', payload, 'No se pudo liberar la IP')
}

export async function checkDnsRecord(payload) {
  return postJson('/api/dns/check', payload, 'No se pudo comprobar el registro DNS')
}

export async function createDnsRecord(payload) {
  return postJson('/api/dns/create', payload, 'No se pudo crear el registro DNS')
}

export async function detectLayer3domain(payload) {
  return postJson('/api/ip/layer3domain', payload, 'No se pudo obtener el layer3domain de la IP')
}

export async function deleteDnsRecord(payload) {
  return postJson('/api/dns/delete', payload, 'No se pudo eliminar el registro DNS')
}

export async function editIp(payload) {
  return postJson('/api/ip/edit', payload, 'No se pudo editar la IP')
}

export async function previewDnsBulk(payload) {
  return postJson('/api/dns/bulk/preview', payload, 'No se pudo previsualizar la carga masiva')
}

export async function previewDnsDeleteBulk(payload) {
  return postJson('/api/dns/bulk/delete/preview', payload, 'No se pudo previsualizar la eliminación masiva')
}

export async function fetchDnsView(payload) {
  return postJson('/api/dns/view', payload, 'No se pudo obtener la vista del DNS')
}

export async function executeDnsDeleteBulk(payload) {
  return postJson('/api/dns/bulk/delete/execute', payload, 'No se pudo eliminar los registros DNS')
}

export async function importIpInfo(payload) {
  return postJson('/api/import/ip-info', payload, 'No se pudieron resolver las IPs para importación')
}

export async function importDryrun(payload) {
  return postJson('/api/import/dryrun', payload, 'No se pudo ejecutar el dryrun de importación')
}

export async function importExecute(payload) {
  return postJson('/api/import/execute', payload, 'No se pudo ejecutar la importación')
}

// API Keys management
export async function generateApiKey(name) {
  return postJson('/api/v1/apikeys/generate', { name: name || undefined }, 'No se pudo generar la API key')
}

export async function listApiKeys() {
  const r = await fetch('/api/v1/apikeys', { credentials: 'include' })
  if (!r.ok) throw new Error('No se pudieron obtener las API keys')
  return await r.json()
}

export async function revokeApiKey(keyPrefix) {
  const r = await fetch(`/api/v1/apikeys/${encodeURIComponent(keyPrefix)}`, {
    method: 'DELETE',
    credentials: 'include'
  })
  if (!r.ok) throw new Error('No se pudo revocar la API key')
  return await r.json()
}
