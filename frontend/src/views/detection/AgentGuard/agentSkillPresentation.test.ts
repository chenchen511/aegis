import { describe, expect, it } from 'vitest'
import { buildAgentSkillHighlightSegments, paginateAgentSkillRows } from './agentSkillPresentation'

describe('Agent Skill presentation helpers', () => {
  it('highlights unicode codepoint spans without interpreting content as HTML', () => {
    const segments = buildAgentSkillHighlightSegments('前置🙂ignore <script>alert(1)</script>后置', [{
      rule_key: 'ASK-PROMPT-001',
      severity: 'high',
      start_codepoint: 3,
      end_codepoint: 9,
    } as never])

    expect(segments).toEqual([
      { text: '前置🙂', hit: false },
      { text: 'ignore', hit: true, title: 'ASK-PROMPT-001 · high' },
      { text: ' <script>alert(1)</script>后置', hit: false },
    ])
  })

  it('merges overlapping findings and clamps pagination to valid pages', () => {
    const segments = buildAgentSkillHighlightSegments('abcdef', [
      { rule_key: 'A', severity: 'high', start_codepoint: 1, end_codepoint: 4 } as never,
      { rule_key: 'B', severity: 'critical', start_codepoint: 3, end_codepoint: 5 } as never,
    ])
    expect(segments[1]).toMatchObject({ text: 'bcde', hit: true })
    expect(segments[1].title).toContain('A · high')
    expect(segments[1].title).toContain('B · critical')

    expect(paginateAgentSkillRows(['a', 'b', 'c'], 99, 2)).toEqual({
      items: ['c'], page: 2, pageSize: 2, pageCount: 2, total: 3,
    })
  })
})
