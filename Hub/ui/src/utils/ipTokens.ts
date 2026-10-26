// IP and CIDR extraction for list imports (scanner inventories, CSV exports).
// Files are split into tokens and each token is validated, instead of
// matched by one regex: compressed IPv6 (`::1`, `fe80::`) has no word
// boundary to anchor on.

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

const isIPv6 = (s: string): boolean => {
  if (!s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return false
  try {
    // The WHATWG URL parser validates IPv6 literals strictly.
    new URL(`http://[${s}]/`)
    return true
  } catch {
    return false
  }
}

export const isAddrOrCidr = (token: string): boolean => {
  const [addr, prefix, extra] = token.split('/')
  if (extra !== undefined || !addr) return false
  const v4 = IPV4.test(addr)
  const v6 = !v4 && isIPv6(addr)
  if (!v4 && !v6) return false
  if (prefix === undefined) return true
  if (!/^\d{1,3}$/.test(prefix)) return false
  return Number(prefix) <= (v4 ? 32 : 128)
}

export const extractAddrs = (text: string): string[] =>
  text.split(/[\s,;"'`|<>()[\]{}]+/).filter(isAddrOrCidr)
