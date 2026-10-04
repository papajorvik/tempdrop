# TempDrop Mail

Instant anonymous temporary disposable email with a modern, high-density 3-column mailbox interface.

## Features

- **3-Column Mailbox Layout**: Left navigation sidebar, compact inbox list, and full-featured email reader panel.
- **Clean SaaS Aesthetics & Dark Mode**: Minimal off-white/light-gray palette with purple accents (`#7c3aed`) and a dedicated **Midnight Obsidian Dark Mode** with luminous violet accents (`#9061f9`), smooth transitions, and high readability (not a simple color inversion).
- **1-Click Theme Switcher**: Easily toggle between Light, Midnight Dark, and System Match directly from the sidebar, mobile header, or Settings modal.
- **Real-Time Temporary Mailbox**: Instant session generation powered by Mail.tm via a serverless proxy.
- **Custom Username**: Set custom username/address for your session via the "Custom" button or Settings.
- **Full Email Management**:
  - Unread indicators & "Mark as read / unread"
  - Star & Save folders with persistent local storage
  - Real-time client-side search across sender, subject, and excerpt
  - 1-hour session expiration countdown with live progress bar
  - Download email (.txt / .eml), copy email body, and delete email
  - Audio notification chime on incoming email
- **Mobile & Tablet Responsive**: Adapts seamlessly to mobile screens with a slide-out drawer navigation and dedicated single-column message reader with back navigation.

## Project Structure

```
tempdrop/
├── index.html        ← Redesigned 3-column frontend
├── api/
│   └── proxy.js      ← Vercel serverless function (stateless Mail.tm backend proxy)
├── server.js         ← Local development server (bridges static files & /api/proxy)
├── package.json      ← Scripts & dependencies config
├── vercel.json       ← Vercel routing configuration
├── .env.example      ← Environment variable template
└── .gitignore        ← Git ignore rules
```

## Running Locally

1. (Optional) Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Start the local development server:
   ```bash
   npm run dev
   ```
3. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Deploying to Vercel

1. Push this repository to GitHub.
2. Import the repository into [Vercel](https://vercel.com).
3. In Project Settings → Environment Variables, add:
   - `SESSION_SECRET`: A secure 32+ character random string (e.g. generated via `openssl rand -hex 32`)
4. Deploy!

