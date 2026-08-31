import type { AgentSkillFinding } from '@/types/agentSkill'

export interface AgentSkillHighlightSegment {
  text: string
  hit: boolean
  title?: string
}

interface HighlightRange {
  start: number
  end: number
  title: string
}

/**
 * Builds escaped-by-Vue text segments from codepoint spans returned by the API.
 * Keeping this as data (rather than HTML) ensures Skill content is never
 * interpreted as markup, even when a file contains HTML, SVG or JavaScript.
 */
export function buildAgentSkillHighlightSegments(
  content: string,
  findings: AgentSkillFinding[] = [],
): AgentSkillHighlightSegment[] {
  const codepoints = Array.from(content)
  if (!codepoints.length) return []

  const ranges = findings
    .map<HighlightRange | null>(finding => {
      const start = Math.max(0, Math.min(codepoints.length, Number(finding.start_codepoint) || 0))
      const end = Math.max(start, Math.min(codepoints.length, Number(finding.end_codepoint) || 0))
      if (end <= start) return null
      return { start, end, title: `${finding.rule_key} · ${finding.severity}` }
    })
    .filter((range): range is HighlightRange => Boolean(range))
    .sort((left, right) => left.start - right.start || left.end - right.end)

  if (!ranges.length) return [{ text: content, hit: false }]

  const merged: HighlightRange[] = []
  for (const range of ranges) {
    const previous = merged[merged.length - 1]
    if (previous && range.start <= previous.end) {
      previous.end = Math.max(previous.end, range.end)
      previous.title = `${previous.title}；${range.title}`
    } else {
      merged.push({ ...range })
    }
  }

  const segments: AgentSkillHighlightSegment[] = []
  let cursor = 0
  for (const range of merged) {
    if (range.start > cursor) segments.push({ text: codepoints.slice(cursor, range.start).join(''), hit: false })
    segments.push({ text: codepoints.slice(range.start, range.end).join(''), hit: true, title: range.title })
    cursor = range.end
  }
  if (cursor < codepoints.length) segments.push({ text: codepoints.slice(cursor).join(''), hit: false })
  return segments
}

export function paginateAgentSkillRows<T>(rows: T[], page: number, pageSize: number) {
  const safePageSize = Math.max(1, Math.floor(pageSize) || 1)
  const total = rows.length
  const pageCount = Math.max(1, Math.ceil(total / safePageSize))
  const safePage = Math.min(pageCount, Math.max(1, Math.floor(page) || 1))
  const start = (safePage - 1) * safePageSize
  return {
    items: rows.slice(start, start + safePageSize),
    page: safePage,
    pageSize: safePageSize,
    pageCount,
    total,
  }
}
