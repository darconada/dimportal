import React, { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'

const fallbackPalette = {
  border: '#1e2d45',
  text: '#e0e7ff',
  muted: '#9aa7c4',
  chipBg: '#0f2652',
  chipText: '#d7e3ff',
  menuBg: '#0b1830',
  panel: '#0c172b',
  tableHeader: '#101c34',
  tableRow: '#0c172b',
  selectBg: '#0c172b'
}

export default function ResultsTable({ rows, loading, totalRows = 0, pageSize = 10, onPageSizeChange, palette, onSubnetAction, searchType }) {
  const [openMenu, setOpenMenu] = useState(null)
  const pageOptions = [10, 50, 100, 'Todas']
  const colors = {
    ...fallbackPalette,
    ...palette,
    panel: palette?.card || fallbackPalette.panel,
    tableHeader: palette?.tableHeader || fallbackPalette.tableHeader,
    tableRow: palette?.tableRow || fallbackPalette.tableRow,
    selectBg: palette?.card || fallbackPalette.selectBg
  }

  const handlePageSize = (value) => {
    if (value === 'Todas') {
      onPageSizeChange?.(0) // 0 = mostrar todas
    } else {
      onPageSizeChange?.(Number(value))
    }
  }

  const handleSubnetAction = (subnet, action, layer3domain, pool) => {
    setOpenMenu(null)
    onSubnetAction?.({ subnet, action, layer3domain, pool })
  }

  const [menuCoords, setMenuCoords] = useState({ top: 0, left: 0 })

  const handleChipClick = (id, event) => {
    const rect = event.currentTarget.getBoundingClientRect()
    setMenuCoords({
      top: rect.bottom + window.scrollY + 6,
      left: rect.left + window.scrollX
    })
    setOpenMenu((prev) => (prev === id ? null : id))
  }

  useEffect(() => {
    const handleScroll = () => setOpenMenu(null)
    const handleResize = () => setOpenMenu(null)
    window.addEventListener('scroll', handleScroll, true)
    window.addEventListener('resize', handleResize)
    return () => {
      window.removeEventListener('scroll', handleScroll, true)
      window.removeEventListener('resize', handleResize)
    }
  }, [])

  if (loading) return <div style={{ color: colors.muted }}>Buscando…</div>
  if (!rows?.length) return <div style={{ color: colors.muted }}>Sin resultados</div>

  const showingCount = rows.length
  const totalCount = totalRows || rows.length
  const allSelected = pageSize === 0 ? 'Todas' : String(pageSize || 10)

  const isDnsMode = searchType === 'dns'
  const isSubnetMode = searchType === 'subnet'
  const isDeviceMode = searchType === 'device'
  const hasDnsView = isDnsMode && rows.some((r) => r.fqdn?.toLowerCase().includes('.arsyscloud.tools') && r.dns_view)
  const columns = isDnsMode
    ? ['FQDN', 'IP', 'VLAN', 'Networks/Subnets', 'Pool', 'Layer3Domain', ...(hasDnsView ? ['Vista'] : []), 'Zona']
    : isSubnetMode
      ? ['Pool', 'VLAN', 'Networks/Subnets', 'Layer3Domain']
      : isDeviceMode
        ? ['IP', 'VLAN', 'Networks/Subnets', 'DNS', 'Vista', 'Comentario', 'Pool', 'Layer3Domain']
        : ['Pool', 'VLAN', 'IP', 'DNS', 'Comentario', 'Networks/Subnets', 'Layer3Domain']

  const renderSubnetsCell = (subnets, layer3domain, pool, baseKey) => {
    if (!subnets?.length) {
      return <span style={{ color: colors.muted }}>—</span>
    }
    return (
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {subnets.map((s) => {
          const id = `${baseKey}-${s}`
          const isOpen = openMenu === id
          return (
            <div key={s} style={{ position: 'relative' }}>
              <span
                style={{
                  display: 'inline-block',
                  background: colors.chipBg,
                  color: colors.chipText,
                  padding: '5px 12px',
                  borderRadius: 999,
                  cursor: 'pointer'
                }}
                onClick={(e) => handleChipClick(id, e)}
              >
                {s}
              </span>
              {isOpen
                ? createPortal(
                    <div
                      style={{
                        position: 'absolute',
                        top: menuCoords?.top || 0,
                        left: menuCoords?.left || 0,
                        background: colors.menuBg,
                        border: `1px solid ${colors.border}`,
                        borderRadius: 10,
                        minWidth: 200,
                        boxShadow: '0 10px 30px rgba(0,0,0,0.4)',
                        overflow: 'hidden',
                        zIndex: 9999
                      }}
                    >
                      {[
                        { key: 'all', label: 'Listar todas las IPs' },
                        { key: 'free', label: 'Listar IPs libres' },
                        { key: 'used', label: 'Listar IPs en uso' }
                      ].map((opt) => (
                        <button
                          key={opt.key}
                          type="button"
                          onClick={() => handleSubnetAction(s, opt.key, layer3domain, pool)}
                          style={{
                            width: '100%',
                            textAlign: 'left',
                            padding: '10px 12px',
                            background: 'transparent',
                            color: colors.text,
                            border: 'none',
                            cursor: 'pointer'
                          }}
                        >
                          {opt.label}
                        </button>
                      ))}
                    </div>,
                    document.body
                  )
                : null}
            </div>
          )
        })}
      </div>
    )
  }

  return (
    <div style={{ background: colors.panel, borderRadius: 10, border: `1px solid ${colors.border}`, position: 'relative', overflow: 'visible' }}>
      <div style={{ overflowX: 'auto', overflowY: 'visible', position: 'relative', paddingBottom: 4 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 700, background: colors.tableRow }}>
          <thead>
            <tr style={{ background: colors.tableHeader }}>
              {columns.map((h) => (
                <th key={h} style={{ textAlign: 'left', padding: '12px 14px', color: colors.text, fontWeight: 700 }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, idx) => {
              const rowKey = r.device || r.fqdn || r.pool || r.ip_address || idx
              return (
                <tr key={rowKey} style={{ borderTop: `1px solid ${colors.border}`, background: colors.tableRow }}>
                  {isDnsMode ? (
                    <>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.fqdn || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.ip_address || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.vlan || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.subnets?.[0] || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.pool}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.layer3domain || '—'}</td>
                      {hasDnsView ? <td style={{ padding: '12px 14px', color: colors.text }}>{r.dns_view || '—'}</td> : null}
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.dns_zone || '—'}</td>
                    </>
                  ) : isSubnetMode ? (
                    <>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.pool}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.vlan || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>
                        {renderSubnetsCell(r.subnets, r.layer3domain, r.pool, `${idx}-subnet`)}
                      </td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.layer3domain || '—'}</td>
                    </>
                  ) : isDeviceMode ? (
                    <>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.ip_address || r.ip || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.vlan || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>
                        {renderSubnetsCell(r.subnets, r.layer3domain, r.pool, `${idx}-device`)}
                      </td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>
                        {r.fqdn || r.ptr_target || r.dns || '—'}
                      </td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.dns_view || r.view || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.comment || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.pool || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.layer3domain || '—'}</td>
                    </>
                  ) : (
                    <>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.pool}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.vlan || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.ip_address || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.ptr_target || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.comment || '—'}</td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>
                        {renderSubnetsCell(r.subnets, r.layer3domain, r.pool, `${idx}-default`)}
                      </td>
                      <td style={{ padding: '12px 14px', color: colors.text }}>{r.layer3domain || '—'}</td>
                    </>
                  )}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 8,
          padding: '10px 14px',
          color: colors.muted
        }}
      >
        <span style={{ color: colors.muted }}>
          {`Mostrando ${showingCount} de ${totalCount} resultados`}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span>Mostrar</span>
          <select
            value={allSelected}
            onChange={(e) => handlePageSize(e.target.value)}
            style={{
              padding: '6px 10px',
              borderRadius: 8,
              border: `1px solid ${colors.border}`,
              background: colors.selectBg,
              color: colors.text
            }}
          >
            {pageOptions.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  )
}
