// Display name for a sensor ID: the manifest name when the catalog has it,
// otherwise the ID without its ts-sensor- prefix.
export const decoyName = (sensorId: string, manifests: { id: string; name: string }[]): string => {
  const m = manifests.find(x => x.id === sensorId)
  if (m?.name) return m.name
  return sensorId.replace(/^ts-sensor-/, '').replace(/-/g, ' ')
}

// Axis-friendly name: drops the parenthetical protocol list
// ("Remote Access Decoy (SSH / Telnet / FTP)" -> "Remote Access Decoy").
export const shortDecoyName = (sensorId: string, manifests: { id: string; name: string }[]): string =>
  decoyName(sensorId, manifests).replace(/\s*\(.*\)\s*$/, '')
