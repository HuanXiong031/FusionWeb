const { existsSync, rmSync, cpSync } = require('fs')
const { join } = require('path')
const { spawnSync } = require('child_process')

const root = join(__dirname, '..')
const outDir = join(root, 'out')
const distDir = join(root, 'dist')

let nextCli
try {
  nextCli = require.resolve('next/dist/bin/next', { paths: [root] })
} catch {
  console.error('Missing frontend dependencies. Run npm install or use the root build script.')
  process.exit(1)
}

const r = spawnSync(process.execPath, [nextCli, 'build'], { cwd: root, stdio: 'inherit' })
if (r.error) {
  console.error(r.error.message)
  process.exit(1)
}
if ((r.status ?? 1) !== 0) {
  process.exit(r.status ?? 1)
}

if (existsSync(distDir)) {
  rmSync(distDir, { recursive: true, force: true })
}
cpSync(outDir, distDir, { recursive: true })
