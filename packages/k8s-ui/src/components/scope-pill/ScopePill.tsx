import type { ReactNode } from 'react'

export interface ScopePillProps {
  /**
   * The scope segments — typically a cluster switcher followed by a namespace
   * picker, each rendered in its `variant="segment"` form (borderless). They're
   * separated by a divider and read as one "what am I looking at" unit.
   */
  children: ReactNode
  className?: string
}

/**
 * ScopePill is the shared bordered shell for the cluster + namespace "scope"
 * control, used by both OSS Radar's header and Radar Hub's cluster top bar so
 * the two stay visually identical. It is purely the container: the segments
 * (ClusterSwitcher / NamespacePicker in segment variant) and their data,
 * view-awareness, and any layout pinning are the host's concern.
 *
 * Deliberately NO `overflow-hidden`: ClusterSwitcher's dropdown renders inline
 * (absolute, not portaled), so clipping this ancestor would hide it. Instead of
 * clipping, the outer corners of the first/last segment's TRIGGER button are
 * rounded (7px = the 8px pill radius minus its 1px border) so each segment's
 * hover/active fill follows the pill's shape instead of poking square corners
 * past it. `>button` targets only the trigger, never the dropdown's buttons.
 */
export function ScopePill({ children, className = '' }: ScopePillProps) {
  return (
    <div
      className={`flex items-stretch shrink-0 rounded-lg border border-theme-border bg-theme-surface divide-x divide-theme-border [&>*:first-child>button]:rounded-l-[7px] [&>*:last-child>button]:rounded-r-[7px] ${className}`}
    >
      {children}
    </div>
  )
}
