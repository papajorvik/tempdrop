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
├── index.html        ← Modern 3-column disposable email frontend
├── server/
│   └── proxy.js      ← Stateless Mail.tm backend proxy & session manager
├── server.js         ← Production Node.js HTTP server (binds 0.0.0.0, /health, /api/proxy)
├── package.json      ← Scripts ("start": "node server.js") & engines config
├── vercel.json       ← Vercel frontend rewrite configuration (routes /api/* to Render)
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

---

## Deploying Backend to Render

Deploy the persistent Node.js backend to [Render](https://render.com) so Mail.tm requests originate from reliable, non-blocked container IP pools.

1. **Create Web Service**:
   - Go to the [Render Dashboard](https://dashboard.render.com).
   - Click **New +** → **Web Service**.
   - Connect your GitHub repository (`papajorvik/tempdrop`).

2. **Configure Settings**:
   - **Name**: `tempdrop-backend` (or your preferred name)
   - **Region**: Frankfurt (EU Central) or Oregon (US West)
   - **Runtime**: `Node`
   - **Branch**: `main`
   - **Build Command**: *(leave empty or enter `npm install`)*
   - **Start Command**: `node server.js` (or `npm start`)
   - **Plan**: `Free`

3. **Configure Environment Variables**:
   In the **Environment Variables** section, add:
   - `SESSION_SECRET`: Your 32+ byte hex key (e.g. `698113cd2c0c308eed46f238a62dd10e6016a4c0d848b44e5d7fded6e99eaf4d`)
   - `NODE_ENV`: `production`

4. **Configure Health Check Path**:
   - Under **Advanced Settings** → **Health Check Path**, enter: `/health`

5. **Deploy**:
   - Click **Create Web Service**.
   - Wait for deployment to complete.
   - Verify by loading `https://<your-render-subdomain>.onrender.com/health` in your browser. You should see `{"status":"ok","service":"tempdrop-backend"}`.

---

## Connecting Vercel Frontend to Render Backend

Once your Render service is live:

1. Copy your Render service URL (e.g. `https://tempdrop-backend-xxxx.onrender.com`).
2. Open `vercel.json` and replace `YOUR_RENDER_SERVICE_URL.onrender.com` with your actual Render service hostname:
   ```json
   {
     "rewrites": [
       {
         "source": "/api/:match*",
         "destination": "https://tempdrop-backend-xxxx.onrender.com/api/:match*"
       }
     ]
   }
   ```
3. Commit and push `vercel.json` to GitHub `main`.
4. Vercel automatically deploys the frontend update. All calls to `/api/proxy` on your Vercel site will now be transparently proxied to Render with first-party same-origin cookies and zero CORS restrictions!

