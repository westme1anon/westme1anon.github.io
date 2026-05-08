# AGENTS.md - Mizuki Astro Blog

## Project Overview

Mizuki is an Astro 5 blog theme with Svelte components, Tailwind CSS, and TypeScript.
Content is managed via Astro Content Collections with Zod schemas.

## Package Manager

**Always use pnpm** (enforced via preinstall script). Never use npm or yarn.

## Build & Development Commands

```bash
# Install dependencies
pnpm install

# Development server
pnpm dev

# Production build (runs bangumi update, astro build, pagefind indexing, font compression)
pnpm build

# Preview production build
pnpm preview

# Astro check (diagnostics)
pnpm check

# Type checking
pnpm type-check

# Format code with Prettier
pnpm format

# Lint with ESLint (auto-fix)
pnpm lint
```

### No Test Framework

This project has no test runner configured. There are no unit or e2e tests.
Verify changes by running `pnpm check` and `pnpm type-check`, then manual testing via `pnpm dev`.

## CI Pipeline

GitHub Actions CI runs on push/PR to master:

- `pnpm astro check` (with `ENABLE_CONTENT_SYNC=false`)
- `pnpm astro build` (with `ENABLE_CONTENT_SYNC=false`)

## Tech Stack

- **Framework**: Astro 5.16 (static output)
- **UI Components**: Astro (.astro) + Svelte 5 (.svelte)
- **Styling**: Tailwind CSS 3 + Stylus + plain CSS
- **Language**: TypeScript (strict null checks, ESNext)
- **Content**: Astro Content Collections with Zod validation
- **Markdown plugins**: remark-math, remark-directive, remark-sectionize, rehype-katex, rehype-slug, rehype-autolink-headings
- **Code blocks**: expressive-code with custom plugins
- **Page transitions**: @swup/astro
- **Icons**: astro-icon + @iconify-json/\*

## Code Style

### Prettier Configuration

- **Indentation**: Tabs, tab width 4 (except CSS: spaces, tab width 2)
- **Print width**: 80 (CSS: 200)
- **Quotes**: Double quotes
- **Semicolons**: Always
- **Trailing commas**: All
- **Line endings**: CRLF
- **Arrow parens**: Always

### TypeScript

- Target: ESNext, module: ESNext, moduleResolution: bundler
- `strictNullChecks: true`
- Use `import type` for type-only imports
- Declaration files: `src/env.d.ts`, `src/global.d.ts`

### Path Aliases (tsconfig.json)

```
@components/*  -> src/components/*
@assets/*      -> src/assets/*
@constants/*   -> src/constants/*
@utils/*       -> src/utils/*
@i18n/*        -> src/i18n/*
@layouts/*     -> src/layouts/*
@/*            -> src/*
```

Always use path aliases for cross-directory imports.

### Naming Conventions

- **Components**: PascalCase filenames (`PostCard.astro`, `Search.svelte`)
- **Utility files**: kebab-case with `-utils` suffix (`url-utils.ts`, `date-utils.ts`)
- **Type files**: camelCase (`config.ts`, `album.ts`)
- **Constants**: camelCase files, UPPER_SNAKE_CASE exports (`PAGE_SIZE`, `LIGHT_MODE`)
- **CSS files**: kebab-case (`mobile-navbar.css`, `panel-animations.css`)
- **Pages**: kebab-case or Astro dynamic routes (`[...page].astro`)

### Component Patterns

**Astro components** (`.astro`):

- Frontmatter in `---` fences uses TypeScript
- Define `interface Props` for component props
- Use `Astro.props` to receive props
- Destructure props at the top of frontmatter

**Svelte components** (`.svelte`):

- Use `<script lang="ts">` for TypeScript
- Import from path aliases (`@utils/`, `@i18n/`, etc.)
- Use `$state`, `$derived`, `$effect` (Svelte 5 runes)

### Imports

- Group imports: external packages first, then path alias imports, then relative imports
- Use `import type` for type-only imports
- Astro content API: `import { CollectionEntry } from "astro:content"`

### Error Handling

- No explicit error handling patterns enforced; use standard try/catch where needed
- Utility functions return simple values, not Result types

## Project Structure

```
src/
  components/       # Astro + Svelte UI components
    widget/         # Sidebar widgets (Profile, Tags, Categories, etc.)
    control/        # Control/UI elements
    comment/        # Comment system components
    misc/           # Miscellaneous components (ImageWrapper, etc.)
    layout/         # Layout sub-components
  content/
    posts/          # Blog posts (markdown), organized by topic folders
    spec/           # Special content pages
  constants/        # App-wide constants
  i18n/             # Internationalization (en, zh_CN, zh_TW, ja)
  layouts/          # Page layouts (Layout.astro, MainGridLayout.astro)
  pages/            # Astro pages and API routes
  plugins/          # Remark/Rehype plugins and expressive-code plugins
  scripts/          # Client-side JS scripts
  styles/           # Global CSS and Stylus files
  types/            # TypeScript type definitions
  utils/            # Utility functions
  config.ts         # Main site configuration (exported config objects)
  content.config.ts # Content collection schema definitions
```

## Content Collections

Posts are defined in `src/content.config.ts` with Zod schema:

- Required: `title` (string), `published` (date)
- Optional: `updated`, `draft`, `description`, `image`, `tags`, `category`, `lang`, `pinned`, `permalink`, `encrypted`, `password`, `alias`

## Configuration

Main config is in `src/config.ts`. All site settings are exported as typed constants:

- `siteConfig` - core site settings
- `navBarConfig` - navigation links
- `profileConfig` - author profile
- `commentConfig` - Twikoo comment system
- `sidebarLayoutConfig` - sidebar widget layout
- And many more specialized configs

## Key Patterns

- The build uses `scripts/sync-content.js` as predev/prebuild hook
- Page search uses Pagefind (indexing runs during build)
- Theme supports light/dark mode toggling via CSS class
- Swup handles page transitions with configurable animation
- Expressive Code provides syntax highlighting with custom copy button and language badge plugins
