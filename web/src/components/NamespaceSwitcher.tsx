import { forwardRef } from 'react'
import { NamespacePicker, type NamespacePickerHandle } from '@skyhook-io/k8s-ui'
import { useNamespaceScope, useSetActiveNamespace } from '../api/client'

export type NamespaceSwitcherHandle = NamespacePickerHandle

interface NamespaceSwitcherProps {
  className?: string
  disabled?: boolean
  disabledTooltip?: string
  variant?: 'chip' | 'segment'
  label?: string
}

/**
 * OSS Radar's namespace scope control — a thin data container over the shared
 * presentational NamespacePicker (@skyhook-io/k8s-ui). Wires Radar's own API
 * hooks; Radar Hub supplies its own container over the per-cluster apiBase.
 */
export const NamespaceSwitcher = forwardRef<NamespaceSwitcherHandle, NamespaceSwitcherProps>(function NamespaceSwitcher(
  { className, disabled, disabledTooltip, variant, label },
  ref,
) {
  const { data: scope, isLoading } = useNamespaceScope()
  const setActive = useSetActiveNamespace()

  return (
    <NamespacePicker
      ref={ref}
      scope={scope}
      loading={isLoading}
      pending={setActive.isPending}
      onApply={namespaces => setActive.mutate({ namespaces })}
      disabled={disabled}
      disabledTooltip={disabledTooltip}
      className={className}
      variant={variant}
      label={label}
    />
  )
})
