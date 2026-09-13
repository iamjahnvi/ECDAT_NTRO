import { UserRound, LogOut } from 'lucide-react'

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : 'Not available'
}

export default function UserProfile({ user, onSignOut }) {
  const name = user?.user_metadata?.full_name || user?.user_metadata?.name || user?.email?.split('@')[0] || 'ECDAT User'
  return (
    <section className="info-page" aria-labelledby="profile-title">
      <div className="info-heading"><UserRound size={26} /><h1 id="profile-title">User Profile</h1></div>
      <p>Your signed-in account and session details.</p>
      <div className="info-card">
        <h2>{name}</h2>
        <dl className="profile-details">
          {[
            ['Email', user?.email || 'Not available'],
            ['Email status', user?.email_confirmed_at ? 'Verified' : 'Not verified'],
            ['Account created', formatDate(user?.created_at)],
            ['Last sign in', formatDate(user?.last_sign_in_at)],
          ].map(([label, value]) => (
            <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
          ))}
        </dl>
        <button className="utility-button" onClick={onSignOut}><LogOut size={16} /> Sign out</button>
      </div>
    </section>
  )
}
