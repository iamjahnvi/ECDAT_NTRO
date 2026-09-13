import { useEffect, useRef, useState } from 'react'
import { Menu, LayoutDashboard, History, UserRound } from 'lucide-react'

export default function HomeMenu({ onNavigate }) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef(null)
  const triggerRef = useRef(null)

  useEffect(() => {
    if (!open) return
    function dismiss(event) {
      if (!rootRef.current?.contains(event.target)) setOpen(false)
    }
    function onKeyDown(event) {
      if (event.key === 'Escape') {
        setOpen(false)
        triggerRef.current?.focus()
      }
    }
    document.addEventListener('pointerdown', dismiss)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', dismiss)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  return (
    <div ref={rootRef} className="home-menu" onBlur={event => {
      if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false)
    }}>
      <button ref={triggerRef} className="utility-button" aria-label="Open navigation menu"
        aria-expanded={open} aria-controls="home-navigation" onClick={() => setOpen(value => !value)}>
        <Menu size={20} />
      </button>
      {open && (
        <nav id="home-navigation" aria-label="Home navigation" className="home-menu-panel">
          {[[LayoutDashboard, 'Dashboard'], [History, 'History'], [UserRound, 'User Profile']].map(([Icon, label]) => (
            <button key={label} onClick={() => { setOpen(false); onNavigate(label) }}>
              <Icon size={17} /> {label}
            </button>
          ))}
        </nav>
      )}
    </div>
  )
}
