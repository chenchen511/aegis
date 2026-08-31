// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import router from '../../../router'
import zhCNApp from '../../../i18n/locales/zh-CN/app'
import enUSApp from '../../../i18n/locales/en-US/app'

describe('Agent Guard navigation contract', () => {
  it('provides the parent and Skill scan menu labels in both locales', () => {
    const expectedKeys = ['agentGuard', 'agentGuardEvents', 'agentGuardEscape', 'agentGuardConfigurations', 'agentSkillSecurity']
    expect(expectedKeys.filter(key => key in zhCNApp.menu)).toEqual(expectedKeys)
    expect(expectedKeys.filter(key => key in enUSApp.menu)).toEqual(expectedKeys)
  })

  it('defines the redirect and the Skill scan page route', () => {
    const routes = router.getRoutes()
    expect(routes.find(route => route.path === '/detection/agent-guard')?.redirect)
      .toBe('/detection/agent-guard/events')
    expect(routes.filter(route => [
      '/detection/agent-guard/events',
      '/detection/agent-guard/escape',
      '/detection/agent-guard/configurations',
    ].includes(route.path))).toHaveLength(3)
    expect(routes.find(route => route.path === '/detection/agent-skill-security')?.meta.permission)
      .toBe('agent_guard:read')
  })
})
