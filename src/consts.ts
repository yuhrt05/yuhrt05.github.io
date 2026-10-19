import type { IconMap, SocialLink, Site, CommentConfig } from '@/types'

export const SITE: Site = {
  title: 'ANe',
  description:
    'CTF write-ups, DFIR research, and SIEM labs.',
  href: 'https://yuhrt05.github.io',
  author: 'ANe',
  locale: 'en-US',
  featuredPostCount: 4,
  postsPerPage: 6,
}

export const NAV_LINKS: SocialLink[] = [
  {
    href: '/blog',
    label: 'blog',
  },
  {
    href: '/tags',
    label: 'tags',
  },
  {
    href: '/archives',
    label: 'archives',
  },
  {
    href: '/authors',
    label: 'authors',
  },
]

export const SOCIAL_LINKS: SocialLink[] = [
  {
    href: 'https://github.com/yuhrt05',
    label: 'GitHub',
  },
  {
    href: 'https://cyberdefenders.org/p/ANe/',
    label: 'CyberDefenders',
  },
  {
    href: '/rss.xml',
    label: 'RSS',
  },
]

export const ICON_MAP: IconMap = {
  Website: 'lucide:globe',
  GitHub: 'lucide:github',
  LinkedIn: 'lucide:linkedin',
  Twitter: 'lucide:twitter',
  Email: 'lucide:mail',
  RSS: 'lucide:rss',
  CyberDefenders: 'simple-icons:cyberdefenders',
}

export const COMMENT: CommentConfig = {
  repo: 'yuhrt05/yuhrt05.github.io',
  repoId: '',
  category: 'Comments',
  categoryId: '',
}
