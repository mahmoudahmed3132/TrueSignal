// MITRE ATT&CK types shared by the event table and the Attack Navigator.
export interface AttackTactic { id: string; name: string }
export interface AttackTechnique { id: string; name: string; tactics: AttackTactic[] }
export interface AttackMapping { primary: AttackTechnique; secondary?: AttackTechnique[] }

export interface TechniqueStat {
  id: string
  name: string
  tactics: string[]
  primaryEvents: number
  secondaryEvents: number
  sources: number
  lastSeen: string
  triggers: string[]
}

export interface AttackProjection {
  timeframe: string
  mappedEvents: number
  techniquesObserved: number
  techniquesCovered: number
  tactics: AttackTactic[]
  techniques: TechniqueStat[]
}

export const techniqueUrl = (id: string): string =>
  `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
