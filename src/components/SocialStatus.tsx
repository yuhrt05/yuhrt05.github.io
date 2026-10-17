import { useEffect, useState } from 'react'

const DEFAULT_DISCORD_ID = ''
const POLL_INTERVAL_MS = 10000

interface Props {
  discordId?: string
  displayName?: string
  fallbackAvatar?: string
}

interface DiscordActivity {
  name: string
  type?: number
  details?: string
  state?: string
  sync_id?: string
  assets?: {
    large_image?: string
    large_text?: string
    small_image?: string
    small_text?: string
  }
}

interface DiscordPresence {
  status: 'online' | 'idle' | 'dnd' | 'offline'
  client_status?: {
    desktop?: DiscordPresence['status']
    mobile?: DiscordPresence['status']
    web?: DiscordPresence['status']
  }
  activities: DiscordActivity[]
}

interface DiscordProfile {
  username: string
  global_name?: string | null
  avatarURL?: string | null
  defaultAvatarURL?: string | null
}

type StatusBadgesResponse =
  | DiscordPresence
  | {
      error?: {
        message?: string
      }
      message?: string
    }

type JapiUserResponse =
  | {
      data: DiscordProfile
    }
  | {
      error?: string
      message?: string
    }

export default function SocialStatus({
  discordId = DEFAULT_DISCORD_ID,
  displayName = '0xGunn',
  fallbackAvatar = 'https://cdn.discordapp.com/embed/avatars/0.png',
}: Props) {
  const [presence, setPresence] = useState<DiscordPresence | null>(null)
  const [profile, setProfile] = useState<DiscordProfile | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true

    const fetchData = async () => {
      if (!discordId) {
        setPresence(null)
        setProfile(null)
        setError('Missing Discord user ID')
        setLoading(false)
        return
      }

      try {
        try {
          const profileResponse = await fetch(
            `https://japi.rest/discord/v1/user/${discordId}`,
            { cache: 'force-cache' },
          )
          const profileJson = (await profileResponse.json()) as JapiUserResponse

          if (mounted && profileResponse.ok && 'data' in profileJson) {
            setProfile(profileJson.data)
          }
        } catch (error) {
          console.error('Failed to fetch Discord profile', error)
        }

        const presenceResponse = await fetch(
          `https://api.statusbadges.me/presence/${discordId}`,
          { cache: 'no-store' },
        )
        const presenceJson =
          (await presenceResponse.json()) as StatusBadgesResponse

        if (!presenceResponse.ok || !('status' in presenceJson)) {
          throw new Error(
            'message' in presenceJson
              ? presenceJson.message ||
                  presenceJson.error?.message ||
                  'Discord status unavailable'
              : `Discord status request failed (${presenceResponse.status})`,
          )
        }

        if (mounted) {
          setPresence(presenceJson)
          setError(null)
        }
      } catch (error) {
        console.error('Failed to fetch Discord presence', error)
        if (mounted) {
          setPresence(null)
          setError(
            error instanceof Error
              ? error.message
              : 'Discord status unavailable',
          )
        }
      } finally {
        if (mounted) {
          setLoading(false)
        }
      }
    }

    fetchData()

    const interval = setInterval(fetchData, POLL_INTERVAL_MS)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [discordId])

  if (loading) {
    return (
      <div className="bg-background/40 h-40 animate-pulse rounded-xl border p-4">
        <div className="bg-muted mb-4 h-4 w-1/3 rounded"></div>
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="bg-muted h-10 w-10 rounded-full"></div>
            <div className="flex-1 space-y-2">
              <div className="bg-muted h-3 w-1/4 rounded"></div>
              <div className="bg-muted h-2 w-1/2 rounded"></div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'bg-green-500'
      case 'idle':
        return 'bg-yellow-500'
      case 'dnd':
        return 'bg-red-500'
      default:
        return 'bg-gray-500'
    }
  }

  const getStatusLabel = (status: DiscordPresence['status']) => {
    switch (status) {
      case 'online':
        return 'Online'
      case 'idle':
        return 'Idle'
      case 'dnd':
        return 'Do not disturb'
      default:
        return 'Offline'
    }
  }

  const getSpotifyAlbumArt = (activity: DiscordActivity) => {
    const image = activity.assets?.large_image

    if (!image) {
      return null
    }

    return image.startsWith('spotify:')
      ? `https://i.scdn.co/image/${image.replace('spotify:', '')}`
      : null
  }

  const activity = presence?.activities.find(
    (activity) =>
      activity.name !== 'Spotify' && (activity.state || activity.details),
  )
  const spotify = presence?.activities.find(
    (activity) => activity.name === 'Spotify' && activity.sync_id,
  )
  const spotifyAlbumArt = spotify ? getSpotifyAlbumArt(spotify) : null
  const avatarUrl =
    profile?.avatarURL || profile?.defaultAvatarURL || fallbackAvatar
  const name = profile?.global_name || profile?.username || displayName
  const statusColor = presence ? getStatusColor(presence.status) : 'bg-gray-500'
  const statusLabel = presence ? getStatusLabel(presence.status) : 'Unavailable'
  const subtitle = activity?.state || activity?.details || statusLabel

  return (
    <div className="bg-background/40 flex flex-col gap-4 rounded-xl border p-4">
      <h3 className="text-foreground/90 flex items-center gap-2 text-sm font-semibold">
        Live Status
        <span
          className={`inline-block h-2 w-2 rounded-full ${statusColor}`}
        ></span>
      </h3>

      <div className="flex flex-col gap-4">
        <div className="flex items-center gap-3">
          <div className="relative shrink-0">
            <img
              src={avatarUrl}
              alt="Discord Avatar"
              className="border-background h-10 w-10 rounded-full border-2 shadow-sm"
            />
            <div
              className={`border-background absolute -right-0.5 -bottom-0.5 h-3.5 w-3.5 rounded-full border-2 ${statusColor}`}
            ></div>
          </div>
          <div className="flex min-w-0 flex-col">
            <span className="text-foreground truncate text-sm font-medium">
              {name}
            </span>
            <span className="text-muted-foreground truncate text-xs">
              {subtitle}
            </span>
          </div>
        </div>

        {spotify ? (
          <div className="flex items-center gap-3 rounded-lg border border-white/10 bg-white/5 p-2">
            {spotifyAlbumArt ? (
              <div className="relative h-10 w-10 shrink-0 overflow-hidden rounded shadow-sm">
                <img
                  src={spotifyAlbumArt}
                  alt="Album Art"
                  className="animate-spin-slow h-full w-full object-cover"
                  style={{ animationDuration: '10s' }}
                />
              </div>
            ) : null}
            <div className="flex min-w-0 flex-col">
              <a
                href={`https://open.spotify.com/track/${spotify.sync_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-foreground truncate text-xs font-medium transition-colors hover:text-green-500 hover:underline"
              >
                {spotify.details || 'Spotify'}
              </a>
              <span className="text-muted-foreground truncate text-xs">
                {spotify.state || 'Listening now'}
              </span>
            </div>
          </div>
        ) : null}

        {error ? (
          <p className="text-muted-foreground text-xs">{error}</p>
        ) : null}
      </div>
    </div>
  )
}
