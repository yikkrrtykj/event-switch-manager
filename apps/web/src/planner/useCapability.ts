import { useEffect, useMemo, useRef, useState } from 'react'
import { capabilityKey, previewCapability } from './capability'
import type { CapabilityId, CapabilityState, CapabilityTarget } from './capability'
import type { Plan } from './model'

export function useDraftCapability(
  plan: Plan, targets: CapabilityTarget[], capabilities: readonly CapabilityId[],
  enabled = true,
) {
  const key = useMemo(
    () => capabilityKey(plan, targets, capabilities),
    [plan, targets, capabilities],
  )
  const [states, setStates] = useState<Record<string, CapabilityState>>({})
  const generation = useRef(0)
  const controllers = useRef(new Map<string, AbortController>())

  useEffect(() => {
    const current = ++generation.current
    for (const controller of controllers.current.values()) controller.abort()
    controllers.current.clear()
    if (!enabled || !targets.length) {
      setStates({})
      return
    }
    setStates((previous) => {
      const next: Record<string, CapabilityState> = {}
      for (const target of targets) {
        const old = previous[target.key]
        next[target.key] = old?.preview
          ? { ...old, status: 'stale' }
          : { status: 'loading', requestKey: key }
      }
      return next
    })
    const timer = window.setTimeout(() => {
      for (const target of targets) {
        const controller = new AbortController()
        controllers.current.set(target.key, controller)
        void previewCapability({
          plan,
          assignment_id: target.assignmentId,
          capabilities: [...capabilities],
          interface_id: target.interfaceId ?? null,
          stack_member: target.stackMember ?? null,
        }, controller.signal).then((preview) => {
          if (generation.current !== current) return
          setStates((previous) => ({
            ...previous,
            [target.key]: { status: 'current', preview, requestKey: key },
          }))
        }, (error: unknown) => {
          if (controller.signal.aborted || generation.current !== current) return
          setStates((previous) => ({
            ...previous,
            [target.key]: {
              status: 'error',
              error: error instanceof Error ? error.message : String(error),
              requestKey: key,
            },
          }))
        })
      }
    }, 180)
    return () => {
      window.clearTimeout(timer)
      for (const controller of controllers.current.values()) controller.abort()
      controllers.current.clear()
    }
  }, [key, enabled]) // The key captures the plan, targets and capability list.

  return useMemo(() => {
    const visible: Record<string, CapabilityState> = {}
    for (const target of targets) {
      const state = states[target.key]
      if (!state) {
        visible[target.key] = { status: 'idle', requestKey: key }
      } else if (state.status === 'current' && state.requestKey !== key) {
        visible[target.key] = { ...state, status: 'stale' }
      } else {
        visible[target.key] = state
      }
    }
    return visible
  }, [key, states, targets])
}
